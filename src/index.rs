//! Reference index: for every string, type, field and method of each DEX, the top-level classes
//! that use it. Built from bytecode, annotations and static values without decompiling, so
//! searches can decompile only the classes that can match, and usages come for free.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::bytecode::{self, Ref};
use crate::dex::{Dex, Value};

pub const STRING: usize = 0;
pub const TYPE: usize = 1;
pub const FIELD: usize = 2;
pub const METHOD: usize = 3;

/// One table's id -> classes. Only ids that some class uses get a row: most ids of a big DEX
/// have none, and a dense table of row starts would cost more than the rows themselves.
#[derive(Default)]
pub struct Rows {
    /// used ids, ascending
    ids: Vec<u32>,
    /// row k is classes[start[k]..start[k + 1]]
    start: Vec<u32>,
    classes: Vec<u32>,
}

impl Rows {
    pub fn get(&self, id: usize) -> &[u32] {
        match self.ids.binary_search(&(id as u32)) {
            Ok(k) => &self.classes[self.start[k] as usize..self.start[k + 1] as usize],
            Err(_) => &[],
        }
    }

    fn build(n: usize, mut pairs: Vec<(u32, u32)>) -> Rows {
        pairs.retain(|p| (p.0 as usize) < n);
        pairs.sort_unstable();
        pairs.dedup();
        let mut r = Rows { ids: Vec::new(), start: Vec::new(), classes: Vec::with_capacity(pairs.len()) };
        for (id, class) in pairs {
            if r.ids.last() != Some(&id) {
                r.ids.push(id);
                r.start.push(r.classes.len() as u32);
            }
            r.classes.push(class);
        }
        r.start.push(r.classes.len() as u32);
        r.ids.shrink_to_fit();
        r.start.shrink_to_fit();
        r
    }
}

/// Per DEX, per table kind (STRING, TYPE, FIELD, METHOD).
pub struct Index {
    pub by_dex: Vec<[Rows; 4]>,
}

impl Index {
    pub fn users(&self, dex: usize, kind: usize, id: usize) -> &[u32] {
        self.by_dex.get(dex).map_or(&[], |t| t[kind].get(id))
    }
}

fn value_refs(v: &Value, out: &mut [Vec<(u32, u32)>; 4], k: u32) {
    match v {
        Value::Str(s) => out[STRING].push((*s, k)),
        Value::Type(t) => out[TYPE].push((*t, k)),
        Value::Field(f) | Value::Enum(f) => out[FIELD].push((*f, k)),
        Value::Method(m) => out[METHOD].push((*m, k)),
        Value::Array(a) => a.iter().for_each(|x| value_refs(x, out, k)),
        Value::Annotation(a) => {
            out[TYPE].push((a.type_idx, k));
            a.elements.iter().for_each(|(_, x)| value_refs(x, out, k));
        }
        _ => {}
    }
}

/// Everything class `c` (one class, not its nested ones) refers to, tagged with top-level `k`.
fn class_refs(dx: &Dex, c: usize, k: u32, out: &mut [Vec<(u32, u32)>; 4]) {
    if let Ok(data) = dx.class_data(c) {
        // a class "uses" the fields it declares: `API_KEY = "..."` constants live there
        out[FIELD].extend(data.fields.iter().map(|&(f, _)| (f, k)));
        for m in &data.methods {
            out[METHOD].push((m.method_idx, k));
            let Some(code) = &m.code else { continue };
            for i in bytecode::decode(code.insns).unwrap_or_default() {
                let Some((_, _, r)) = bytecode::info(i.op) else { continue };
                match r {
                    Ref::String => out[STRING].push((i.idx, k)),
                    Ref::Type => out[TYPE].push((i.idx, k)),
                    Ref::Field => out[FIELD].push((i.idx, k)),
                    Ref::Method => out[METHOD].push((i.idx, k)),
                    _ => {}
                }
            }
        }
    }
    if let Ok(vals) = dx.static_values(c) {
        vals.iter().for_each(|v| value_refs(v, out, k));
    }
    if let Ok(a) = dx.annotations(c) {
        let all = a.class.iter().chain(a.fields.values().flatten()).chain(a.methods.values().flatten()).chain(a.params.values().flatten().flatten());
        for ann in all {
            value_refs(&Value::Annotation(ann.clone()), out, k);
        }
    }
}

/// `classes`: the top-level classes as (dex, class index); their position is the class id.
pub fn build(dexes: &[Dex], classes: &[(usize, usize)], threads: usize, done: &AtomicUsize) -> Index {
    let next = AtomicUsize::new(0);
    // per dex, per kind: (id, class) pairs from all threads
    let parts: Mutex<Vec<[Vec<(u32, u32)>; 4]>> = Mutex::new((0..dexes.len()).map(|_| Default::default()).collect());
    std::thread::scope(|s| {
        for _ in 0..threads.max(1) {
            s.spawn(|| {
                let mut local: Vec<[Vec<(u32, u32)>; 4]> = (0..dexes.len()).map(|_| Default::default()).collect();
                loop {
                    let k = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&(d, c)) = classes.get(k) else { break };
                    let dx = &dexes[d];
                    // the class and every class nested in it
                    let mut stack = vec![c];
                    while let Some(x) = stack.pop() {
                        class_refs(dx, x, k as u32, &mut local[d]);
                        stack.extend(dx.nesting().kids[x].iter());
                    }
                    done.fetch_add(1, Ordering::Relaxed);
                }
                let mut all = parts.lock().unwrap();
                for (d, kinds) in local.into_iter().enumerate() {
                    for (t, v) in kinds.into_iter().enumerate() {
                        all[d][t].extend(v);
                    }
                }
            });
        }
    });
    let by_dex = parts
        .into_inner()
        .unwrap()
        .into_iter()
        .zip(dexes)
        .map(|(kinds, dx)| {
            let n = dx.counts();
            let [a, b, c, d] = kinds;
            [Rows::build(n[0], a), Rows::build(n[1], b), Rows::build(n[2], c), Rows::build(n[3], d)]
        })
        .collect();
    Index { by_dex }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_group_and_dedup() {
        let r = Rows::build(4, vec![(2, 7), (0, 1), (2, 3), (2, 7), (9, 9)]);
        assert_eq!(r.get(0), &[1]);
        assert_eq!(r.get(1), &[] as &[u32]);
        assert_eq!(r.get(2), &[3, 7]);
        // out-of-range ids are dropped, lookups past the end are empty
        assert_eq!(r.get(9), &[] as &[u32]);
    }
}
