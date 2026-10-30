//! Method-level passes over the expression tree: inlining, condition merging, variable splitting.

use std::collections::HashMap;

use crate::cfg::{Cfg, Term};
use crate::ir::{Expr, Stmt, Vars};

/// per block: statements and terminator condition/key
pub type Bir = Vec<(Vec<Stmt>, Option<Expr>)>;

fn bit(s: &[u64], i: usize) -> bool {
    s[i / 64] >> (i % 64) & 1 != 0
}
fn set(s: &mut [u64], i: usize) {
    s[i / 64] |= 1 << (i % 64);
}

fn succs_all(cfg: &Cfg, b: usize) -> Vec<usize> {
    let blk = &cfg.blocks[b];
    blk.succs().into_iter().chain(blk.handlers.iter().map(|h| h.1)).collect()
}

/// registers live at the end of each block
fn live_out(cfg: &Cfg, bir: &Bir, nregs: usize) -> Vec<Vec<u64>> {
    let n = cfg.blocks.len();
    let w = nregs.div_ceil(64).max(1);
    let (mut uses, mut defs) = (vec![vec![0u64; w]; n], vec![vec![0u64; w]; n]);
    for b in 0..n {
        let (stmts, cond) = &bir[b];
        let (u, d) = (&mut uses[b], &mut defs[b]);
        let mut read = |r: u16, d: &[u64], u: &mut [u64]| {
            if (r as usize) < nregs && !bit(d, r as usize) { set(u, r as usize) }
        };
        for s in stmts {
            for e in s.exprs() {
                e.for_each_reg(&mut |r| read(r, d, u));
            }
            if let Some(r) = s.def().filter(|&r| (r as usize) < nregs) {
                set(d, r as usize);
            }
        }
        if let Some(c) = cond {
            c.for_each_reg(&mut |r| read(r, d, u));
        }
    }
    let succs: Vec<Vec<usize>> = (0..n).map(|b| succs_all(cfg, b)).collect();
    let mut inn = uses.clone();
    let mut out = vec![vec![0u64; w]; n];
    let mut changed = true;
    while changed {
        changed = false;
        for b in (0..n).rev() {
            for &s in &succs[b] {
                for k in 0..w {
                    out[b][k] |= inn[s][k];
                }
            }
            for k in 0..w {
                let v = uses[b][k] | (out[b][k] & !defs[b][k]);
                if v != inn[b][k] {
                    inn[b][k] = v;
                    changed = true;
                }
            }
        }
    }
    out
}

/// is `r` read before being redefined, from `stmts[from..]` through the block end?
fn live_after(stmts: &[Stmt], from: usize, r: u16, cond: &Option<Expr>, out: &[u64]) -> bool {
    for s in stmts.iter().skip(from) {
        if s.reads(r) > 0 {
            return true;
        }
        if s.def() == Some(r) {
            return false;
        }
    }
    cond.as_ref().is_some_and(|c| c.count_reg(r) > 0) || ((r as usize) < out.len() * 64 && bit(out, r as usize))
}

/// Replace the single `Reg(r)` in `exprs` (evaluation order) with `e`, unless that would move a
/// side effect of `e` past another side effect.
fn substitute(exprs: Vec<&mut Expr>, r: u16, e: &Expr) -> bool {
    fn find(x: &Expr, r: u16, impure: &mut bool) -> bool {
        if let Expr::Reg(y) = x {
            return *y == r;
        }
        for c in x.children() {
            if find(c, r, impure) {
                return true;
            }
            if !c.is_pure() {
                *impure = true;
            }
        }
        false
    }
    let mut impure = false;
    for x in &exprs {
        if find(x, r, &mut impure) {
            break;
        }
        if !x.is_pure() {
            impure = true;
        }
    }
    if impure && !e.is_pure() {
        return false;
    }
    let mut done = false;
    for x in exprs {
        x.rewrite_regs(&mut |y| (y == r && !std::mem::replace(&mut done, true)).then(|| e.clone()));
    }
    done
}

/// Fold single-use temporaries into their use; drop dead pure assignments.
pub fn inline(cfg: &Cfg, bir: &mut Bir, nregs: usize) {
    let live = live_out(cfg, bir, nregs);
    for (b, (stmts, cond)) in bir.iter_mut().enumerate() {
        let out = &live[b];
        let mut i = stmts.len();
        while i > 0 {
            i -= 1;
            let Stmt::Assign(Expr::Reg(r), e) = &stmts[i] else { continue };
            let (r, e) = (*r, e.clone());
            if e == Expr::Caught {
                continue;
            }
            let has_next = i + 1 < stmts.len();
            let next_reads = if has_next { stmts[i + 1].reads(r) } else { cond.as_ref().map_or(0, |c| c.count_reg(r)) };
            let later = if !has_next {
                (r as usize) < out.len() * 64 && bit(out, r as usize)
            } else if stmts[i + 1].def() == Some(r) {
                false
            } else {
                live_after(stmts, i + 2, r, cond, out)
            };
            if next_reads == 1 && !later {
                let ok = if has_next { substitute(stmts[i + 1].exprs_mut(), r, &e) } else { substitute(cond.iter_mut().collect(), r, &e) };
                if ok {
                    stmts.remove(i);
                }
                continue;
            }
            if next_reads == 0 && !live_after(stmts, i + 1, r, cond, out) {
                // dead value: keep only real side effects
                if matches!(e, Expr::Invoke(..) | Expr::New(..) | Expr::Custom(..)) {
                    stmts[i] = Stmt::Do(e);
                } else {
                    stmts.remove(i);
                }
            }
        }
    }
}

/// Point edges past blocks that are empty except for a goto. Returns true if anything changed.
fn thread_jumps(cfg: &mut Cfg, bir: &Bir) -> bool {
    let n = cfg.blocks.len();
    let target = |mut b: usize| {
        for _ in 0..n {
            match cfg.blocks[b].term {
                Term::Goto(t) if bir[b].0.is_empty() && t != b => b = t,
                _ => break,
            }
        }
        b
    };
    let mut any = false;
    let new: Vec<Term> = cfg
        .blocks
        .iter()
        .map(|blk| {
            let t = match &blk.term {
                Term::Goto(x) => Term::Goto(target(*x)),
                Term::If { taken, fall } => Term::If { taken: target(*taken), fall: target(*fall) },
                Term::Switch { cases, default } => Term::Switch { cases: cases.iter().map(|&(k, x)| (k, target(x))).collect(), default: target(*default) },
                Term::Exit => Term::Exit,
            };
            any |= t != blk.term;
            t
        })
        .collect();
    for (blk, t) in cfg.blocks.iter_mut().zip(new) {
        blk.term = t;
    }
    any
}

/// `if (a) {if (b) X}` chains -> `if (a && b) X`, and the `||` forms. Returns true if the graph changed.
pub fn merge_conditions(cfg: &mut Cfg, bir: &mut Bir) -> bool {
    let mut any = thread_jumps(cfg, bir);
    'again: loop {
        let n = cfg.blocks.len();
        let mut preds = vec![0usize; n];
        for b in 0..n {
            for s in succs_all(cfg, b) {
                preds[s] += 1;
            }
        }
        for b in 0..n {
            let Term::If { taken: t, fall: f } = cfg.blocks[b].term else { continue };
            for s_is_fall in [true, false] {
                let s = if s_is_fall { f } else { t };
                if s == b || preds[s] != 1 || !bir[s].0.is_empty() || cfg.blocks[s].handlers != cfg.blocks[b].handlers {
                    continue;
                }
                let Term::If { taken: t2, fall: f2 } = cfg.blocks[s].term else { continue };
                let (Some(c), Some(d)) = (bir[b].1.clone(), bir[s].1.clone()) else { continue };
                let (c, d) = (Box::new(c), Box::new(d));
                let merged = if s_is_fall {
                    if t2 == t { Some((Expr::Or(c, d), t, f2)) } else if f2 == t { Some((Expr::Or(c, Box::new(d.negate())), t, t2)) } else { None }
                } else if f2 == f {
                    Some((Expr::And(c, d), t2, f))
                } else if t2 == f {
                    Some((Expr::And(c, Box::new(d.negate())), f2, f))
                } else {
                    None
                };
                let Some((cond, taken, fall)) = merged else { continue };
                bir[b].1 = Some(cond);
                cfg.blocks[b].term = Term::If { taken, fall };
                // s is now unreachable
                cfg.blocks[s].term = Term::Exit;
                cfg.blocks[s].handlers.clear();
                bir[s] = (vec![], None);
                any = true;
                continue 'again;
            }
        }
        return any;
    }
}

/// shortcut: reaching-definitions bitsets are skipped (registers stay raw) above this many bits
const MAX_BITS: usize = 1 << 26;

/// Split registers into variables: definitions that reach a common use are one variable.
/// `params` = registers defined on entry. Rewrites Reg -> Var. Returns None when the method is too big.
pub fn webs(cfg: &Cfg, bir: &mut Bir, params: &[u16]) -> Option<Vars> {
    let n = cfg.blocks.len();
    let mut def_reg: Vec<u16> = params.to_vec();
    let mut def_block: Vec<usize> = vec![usize::MAX; params.len()];
    for (b, (stmts, _)) in bir.iter().enumerate() {
        for s in stmts {
            if let Some(r) = s.def() {
                def_reg.push(r);
                def_block.push(b);
            }
        }
    }
    let nd = def_reg.len();
    if nd * n > MAX_BITS {
        return None;
    }
    let w = nd.div_ceil(64).max(1);
    let mut by_reg: HashMap<u16, Vec<usize>> = HashMap::new();
    for (d, &r) in def_reg.iter().enumerate() {
        by_reg.entry(r).or_default().push(d);
    }
    // gen = last def per reg in block, kill = all defs of regs the block defines, all = every def in block
    let (mut gen_, mut kill, mut all) = (vec![vec![0u64; w]; n], vec![vec![0u64; w]; n], vec![vec![0u64; w]; n]);
    let mut id = params.len();
    for (b, (stmts, _)) in bir.iter().enumerate() {
        let mut last: HashMap<u16, usize> = HashMap::new();
        for s in stmts {
            if let Some(r) = s.def() {
                last.insert(r, id);
                set(&mut all[b], id);
                id += 1;
            }
        }
        for (r, d) in last {
            set(&mut gen_[b], d);
            for &k in &by_reg[&r] {
                set(&mut kill[b], k);
            }
        }
    }
    let mut inn = vec![vec![0u64; w]; n];
    for d in 0..params.len() {
        set(&mut inn[0], d);
    }
    let mut out = vec![vec![0u64; w]; n];
    let mut changed = true;
    while changed {
        changed = false;
        for b in 0..n {
            for k in 0..w {
                let v = gen_[b][k] | (inn[b][k] & !kill[b][k]);
                if v != out[b][k] {
                    out[b][k] = v;
                    changed = true;
                }
            }
            let blk = &cfg.blocks[b];
            for s in blk.succs() {
                for k in 0..w {
                    let v = inn[s][k] | out[b][k];
                    if v != inn[s][k] {
                        inn[s][k] = v;
                        changed = true;
                    }
                }
            }
            // an exception may leave from anywhere inside the block
            for &(_, h) in &blk.handlers {
                for k in 0..w {
                    let v = inn[h][k] | inn[b][k] | all[b][k];
                    if v != inn[h][k] {
                        inn[h][k] = v;
                        changed = true;
                    }
                }
            }
        }
    }
    let mut parent: Vec<usize> = (0..nd).collect();
    fn find(p: &mut [usize], mut x: usize) -> usize {
        while p[x] != x {
            p[x] = p[p[x]];
            x = p[x];
        }
        x
    }
    let mut id = params.len();
    for (b, (stmts, cond)) in bir.iter_mut().enumerate() {
        let mut local: HashMap<u16, usize> = HashMap::new();
        let inb = &inn[b];
        let mut use_reg = |r: u16, local: &HashMap<u16, usize>, parent: &mut Vec<usize>| -> Option<Expr> {
            let cands: Vec<usize> = match local.get(&r) {
                Some(&d) => vec![d],
                None => by_reg.get(&r).map(|v| v.iter().copied().filter(|&d| bit(inb, d)).collect()).unwrap_or_default(),
            };
            let first = *cands.first()?;
            for &c in &cands[1..] {
                let (a, b) = (find(parent, first), find(parent, c));
                parent[a] = b;
            }
            Some(Expr::Var(first))
        };
        for s in stmts.iter_mut() {
            for e in s.exprs_mut() {
                e.rewrite_regs(&mut |r| use_reg(r, &local, &mut parent));
            }
            if let Stmt::Assign(t @ Expr::Reg(_), _) = s {
                let Expr::Reg(r) = *t else { unreachable!() };
                *t = Expr::Var(id);
                local.insert(r, id);
                id += 1;
            }
        }
        if let Some(c) = cond {
            c.rewrite_regs(&mut |r| use_reg(r, &local, &mut parent));
        }
    }
    let root: Vec<usize> = (0..nd).map(|d| find(&mut parent, d)).collect();
    let mut defs = vec![0usize; nd];
    let mut param = vec![false; nd];
    for d in 0..nd {
        if d < params.len() { param[root[d]] = true } else { defs[root[d]] += 1 }
    }
    let _ = def_block;
    Some(Vars { root, defs, param, ty: vec![None; nd], name: vec![String::new(); nd] })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Expr::*;

    #[test]
    fn substitute_respects_order() {
        let call = |m| Invoke(crate::ir::Call::Static, m, vec![]);
        // v0 = f(); use(g(), v0) must not become use(g(), f())
        let mut target = Invoke(crate::ir::Call::Static, 9, vec![call(1), Reg(0)]);
        assert!(!substitute(vec![&mut target], 0, &call(2)));
        let mut target = Invoke(crate::ir::Call::Static, 9, vec![Reg(0), call(1)]);
        assert!(substitute(vec![&mut target], 0, &call(2)));
        assert_eq!(target, Invoke(crate::ir::Call::Static, 9, vec![call(2), call(1)]));
    }
}
