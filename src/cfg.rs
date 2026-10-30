//! Basic blocks, edges and (post)dominators for one method.

use crate::bytecode::Insn;
use crate::dex::Try;

#[derive(Debug, PartialEq)]
pub enum Term {
    /// falls through or jumps unconditionally
    Goto(usize),
    /// `taken` when the condition holds, else `fall`
    If { taken: usize, fall: usize },
    Switch { cases: Vec<(i32, usize)>, default: usize },
    /// return or throw
    Exit,
}

pub struct Block {
    /// insn index range, inclusive
    pub first: usize,
    pub last: usize,
    pub term: Term,
    /// (exception type_idx or None for catch-all, handler block)
    pub handlers: Vec<(Option<u32>, usize)>,
}

pub struct Cfg {
    pub blocks: Vec<Block>,
    /// immediate dominator over normal + exception edges; roots point to themselves
    pub idom: Vec<usize>,
    /// immediate post-dominator over normal edges; None = only reaches exit / never exits
    pub ipdom: Vec<Option<usize>>,
}

impl Block {
    pub fn succs(&self) -> Vec<usize> {
        match &self.term {
            Term::Goto(t) => vec![*t],
            Term::If { taken, fall } => vec![*fall, *taken],
            Term::Switch { cases, default } => {
                let mut v: Vec<usize> = cases.iter().map(|c| c.1).chain([*default]).collect();
                v.dedup();
                v
            }
            Term::Exit => vec![],
        }
    }
}

fn w(units: &[u8], i: usize) -> Result<u32, String> {
    units.get(i * 2..i * 2 + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as u32).ok_or("payload past end".into())
}

/// (key, target code-unit offset) pairs of the switch at `insn`
fn switch_targets(units: &[u8], insn: &Insn) -> Result<Vec<(i32, u32)>, String> {
    let p = (insn.off as i64 + insn.lit) as usize;
    let size = w(units, p + 1)? as usize;
    let i32_at = |i: usize| -> Result<i32, String> { Ok((w(units, i)? | w(units, i + 1)? << 16) as i32) };
    let target = |rel: i32| (insn.off as i64 + rel as i64) as u32;
    let mut out = Vec::with_capacity(size);
    if insn.op == 0x2b {
        let first = i32_at(p + 2)?;
        for k in 0..size {
            out.push((first.wrapping_add(k as i32), target(i32_at(p + 4 + k * 2)?)));
        }
    } else {
        for k in 0..size {
            out.push((i32_at(p + 2 + k * 2)?, target(i32_at(p + 2 + size * 2 + k * 2)?)));
        }
    }
    Ok(out)
}

pub fn build(insns: &[Insn], units: &[u8], tries: &[Try]) -> Result<Cfg, String> {
    if insns.is_empty() {
        return Err("empty method".into());
    }
    let n_units = units.len() / 2;
    let mut leader = vec![false; n_units + 1];
    let mut at = vec![usize::MAX; n_units + 1]; // code unit -> insn index
    for (k, i) in insns.iter().enumerate() {
        at[i.off as usize] = k;
    }
    let mut mark = |off: i64, leader: &mut Vec<bool>| -> Result<(), String> {
        let o = usize::try_from(off).ok().filter(|&o| o < n_units && at[o] != usize::MAX);
        leader[o.ok_or(format!("jump to bad offset {off:#x}"))?] = true;
        Ok(())
    };
    leader[0] = true;
    for (k, i) in insns.iter().enumerate() {
        let next = insns.get(k + 1).map(|n| n.off as i64);
        let ends = match i.op {
            0x0e..=0x11 | 0x27 => true,
            0x28..=0x2a | 0x32..=0x3d => {
                mark(i.off as i64 + i.lit, &mut leader)?;
                true
            }
            0x2b | 0x2c => {
                for (_, t) in switch_targets(units, i)? {
                    mark(t as i64, &mut leader)?;
                }
                true
            }
            _ => false,
        };
        if let (true, Some(n)) = (ends, next) {
            leader[n as usize] = true;
        }
    }
    for t in tries {
        mark(t.start as i64, &mut leader)?;
        let end = (t.start + t.count) as usize;
        if end < n_units && at[end] != usize::MAX {
            leader[end] = true;
        }
        for &(_, h) in &t.handlers {
            mark(h as i64, &mut leader)?;
        }
    }
    // block id of each leader offset
    let starts: Vec<usize> = (0..insns.len()).filter(|&k| leader[insns[k].off as usize]).collect();
    let block_of = |off: i64| -> usize {
        let k = at[off as usize];
        starts.partition_point(|&s| s <= k) - 1
    };
    let mut blocks = Vec::with_capacity(starts.len());
    for (b, &first) in starts.iter().enumerate() {
        let last = starts.get(b + 1).map_or(insns.len() - 1, |&s| s - 1);
        let i = &insns[last];
        let fall = || insns.get(last + 1).map(|n| block_of(n.off as i64)).ok_or("falls off end of method");
        let term = match i.op {
            0x0e..=0x11 | 0x27 => Term::Exit,
            0x28..=0x2a => Term::Goto(block_of(i.off as i64 + i.lit)),
            0x32..=0x3d => Term::If { taken: block_of(i.off as i64 + i.lit), fall: fall()? },
            0x2b | 0x2c => Term::Switch {
                cases: switch_targets(units, i)?.into_iter().map(|(k, t)| (k, block_of(t as i64))).collect(),
                default: fall()?,
            },
            // alignment nop before a trailing payload is unreachable, not a real fall-off
            _ if last + 1 == insns.len() && i.op == 0x00 => Term::Exit,
            _ => Term::Goto(fall()?),
        };
        let off = insns[first].off;
        let handlers = tries
            .iter()
            .filter(|t| (t.start..t.start + t.count).contains(&off))
            .flat_map(|t| t.handlers.iter().map(|&(ty, h)| (ty, block_of(h as i64))))
            .collect();
        blocks.push(Block { first, last, term, handlers });
    }

    let mut cfg = Cfg { blocks, idom: vec![], ipdom: vec![] };
    cfg.recompute();
    Ok(cfg)
}

impl Cfg {
    /// refresh (post)dominators after edges changed
    pub fn recompute(&mut self) {
        let blocks = &self.blocks;
        let n = blocks.len();
        let fwd: Vec<Vec<usize>> = blocks.iter().map(|b| b.succs().into_iter().chain(b.handlers.iter().map(|h| h.1)).collect()).collect();
        self.idom = dominators(&fwd, &[0]).into_iter().enumerate().map(|(b, d)| d.unwrap_or(b)).collect();
        let mut rev = vec![vec![]; n];
        for (b, blk) in blocks.iter().enumerate() {
            for s in blk.succs() {
                rev[s].push(b);
            }
        }
        let exits: Vec<usize> = (0..n).filter(|&b| blocks[b].term == Term::Exit).collect();
        self.ipdom = dominators(&rev, &exits);
    }
}

/// Cooper-Harvey-Kennedy. Returns idom per node; None for roots and unreachable nodes.
pub fn dominators(succ: &[Vec<usize>], roots: &[usize]) -> Vec<Option<usize>> {
    let n = succ.len();
    let root = n; // virtual root above all `roots`
    let mut order = Vec::with_capacity(n + 1); // postorder
    let mut seen = vec![false; n + 1];
    let mut stack = vec![(root, 0usize)];
    seen[root] = true;
    let kids = |v: usize| -> &[usize] { if v == root { roots } else { &succ[v] } };
    while let Some((v, i)) = stack.pop() {
        if let Some(&c) = kids(v).get(i) {
            stack.push((v, i + 1));
            if !seen[c] {
                seen[c] = true;
                stack.push((c, 0));
            }
        } else {
            order.push(v);
        }
    }
    let mut po = vec![usize::MAX; n + 1];
    for (k, &v) in order.iter().enumerate() {
        po[v] = k;
    }
    let mut preds = vec![vec![]; n + 1];
    for &v in &order {
        for &c in kids(v) {
            preds[c].push(v);
        }
    }
    let mut idom = vec![usize::MAX; n + 1];
    idom[root] = root;
    let mut changed = true;
    while changed {
        changed = false;
        for &v in order.iter().rev().skip(1) {
            let mut new = usize::MAX;
            for &p in &preds[v] {
                if idom[p] == usize::MAX {
                    continue;
                }
                new = if new == usize::MAX { p } else {
                    let (mut a, mut b) = (p, new);
                    while a != b {
                        while po[a] < po[b] { a = idom[a]; }
                        while po[b] < po[a] { b = idom[b]; }
                    }
                    a
                };
            }
            if idom[v] != new {
                idom[v] = new;
                changed = true;
            }
        }
    }
    (0..n).map(|v| Some(idom[v]).filter(|&d| d != usize::MAX && d != root)).collect()
}

impl Cfg {
    pub fn dominates(&self, a: usize, mut b: usize) -> bool {
        loop {
            if a == b {
                return true;
            }
            let d = self.idom[b];
            if d == b {
                return false;
            }
            b = d;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diamond() {
        // 0 -> 1,2 -> 3
        let g = vec![vec![1, 2], vec![3], vec![3], vec![]];
        assert_eq!(dominators(&g, &[0]), vec![None, Some(0), Some(0), Some(0)]);
        let rev = vec![vec![], vec![0], vec![0], vec![1, 2]];
        assert_eq!(dominators(&rev, &[3]), vec![Some(3), Some(3), Some(3), None]);
    }

    #[test]
    fn if_and_loop_blocks() {
        use crate::bytecode::decode;
        let enc = |u: &[u16]| u.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<u8>>();
        // 0: if-eqz v0, +3 ; 2: const/4 v0,1 ; 3: goto -3 ; 4: return-void
        let units = enc(&[0x0038, 0x0004, 0x1012, 0xfd28, 0x000e]);
        let insns = decode(&units).unwrap();
        let cfg = build(&insns, &units, &[]).unwrap();
        assert_eq!(cfg.blocks.len(), 3);
        assert_eq!(cfg.blocks[0].term, Term::If { taken: 2, fall: 1 });
        assert_eq!(cfg.blocks[1].term, Term::Goto(0));
        assert!(cfg.dominates(0, 1));
        assert_eq!(cfg.ipdom[0], Some(2));
    }
}
