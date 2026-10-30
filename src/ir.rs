//! Expression tree for one method: lowering from bytecode, typing/naming, Java rendering.

use std::collections::HashMap;

use crate::bytecode::Insn;
use crate::cfg::Term;
use crate::dex::{self, Dex};
use crate::imports::type_ref;

type R<T> = Result<T, String>;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Call { Static, Virtual, Super, Direct, Interface, Poly }

#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    /// raw register, before (or without) variable analysis
    Reg(u16),
    /// variable = id of one of its definitions; resolved via `Vars::root`
    Var(usize),
    /// value, is-wide
    Lit(i64, bool),
    Str(String),
    Class(String),
    Caught,
    /// receiver (None = static), field_idx
    Field(Option<Box<Expr>>, u32),
    /// args include the receiver for non-static calls
    Invoke(Call, u32, Vec<Expr>),
    /// type, ctor method_idx, args (without receiver)
    New(String, u32, Vec<Expr>),
    NewArray(String, Box<Expr>),
    Filled(String, Vec<Expr>),
    /// op, operand/result type (I J F D), lhs, rhs
    Bin(&'static str, char, Box<Expr>, Box<Expr>),
    /// prefix (`-`, `~`, `(long) `), result type
    Un(&'static str, char, Box<Expr>),
    Cast(String, Box<Expr>),
    InstanceOf(Box<Expr>, String),
    ArrayGet(Box<Expr>, Box<Expr>),
    ArrayLen(Box<Expr>),
    /// `Float.compare`-style three-way compare
    Compare(&'static str, Box<Expr>, Box<Expr>),
    /// boolean condition
    Cmp(&'static str, Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    /// invoke-custom call site, args
    Custom(u32, Vec<Expr>),
    /// fill-array-data into an existing array: values (float/double as raw bits)
    Fill(Box<Expr>, Vec<i64>),
    /// `new int[]{1, 2}`: array descriptor, values
    ArrayLit(String, Vec<i64>),
    /// string concatenation: parts with the parameter type of the `append` that added them
    Concat(Vec<(Expr, String)>),
    Raw(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Stmt {
    /// target is Reg or Var
    Assign(Expr, Expr),
    /// lvalue is Field or ArrayGet
    Store(Expr, Expr),
    Do(Expr),
    Return(Option<Expr>),
    Throw(Expr),
    Monitor(bool, Expr),
    Nop,
}

use Expr::*;

fn bx(e: Expr) -> Box<Expr> {
    Box::new(e)
}

impl Expr {
    /// sub-expressions in Java evaluation order
    pub fn children(&self) -> Vec<&Expr> {
        match self {
            Field(Some(o), _) => vec![&**o],
            Invoke(_, _, a) | New(_, _, a) | Filled(_, a) | Custom(_, a) => a.iter().collect(),
            Concat(p) => p.iter().map(|x| &x.0).collect(),
            NewArray(_, a) | Un(_, _, a) | Cast(_, a) | InstanceOf(a, _) | ArrayLen(a) | Not(a) | Fill(a, _) => vec![&**a],
            Bin(_, _, a, b) | ArrayGet(a, b) | Cmp(_, a, b) | And(a, b) | Or(a, b) | Compare(_, a, b) => vec![&**a, &**b],
            _ => vec![],
        }
    }

    pub fn children_mut(&mut self) -> Vec<&mut Expr> {
        match self {
            Field(Some(o), _) => vec![&mut **o],
            Invoke(_, _, a) | New(_, _, a) | Filled(_, a) | Custom(_, a) => a.iter_mut().collect(),
            Concat(p) => p.iter_mut().map(|x| &mut x.0).collect(),
            NewArray(_, a) | Un(_, _, a) | Cast(_, a) | InstanceOf(a, _) | ArrayLen(a) | Not(a) | Fill(a, _) => vec![&mut **a],
            Bin(_, _, a, b) | ArrayGet(a, b) | Cmp(_, a, b) | And(a, b) | Or(a, b) | Compare(_, a, b) => vec![&mut **a, &mut **b],
            _ => vec![],
        }
    }

    /// no side effects and nothing a side effect could change
    pub fn is_pure(&self) -> bool {
        match self {
            Field(..) | Invoke(..) | New(..) | Concat(..) | NewArray(..) | Filled(..) | ArrayGet(..) | Custom(..) | Fill(..) | Raw(_) | Caught => false,
            _ => self.children().iter().all(|c| c.is_pure()),
        }
    }

    pub fn count_reg(&self, r: u16) -> usize {
        match self {
            Reg(x) => (*x == r) as usize,
            _ => self.children().iter().map(|c| c.count_reg(r)).sum(),
        }
    }

    pub fn for_each_reg(&self, f: &mut impl FnMut(u16)) {
        match self {
            Reg(x) => f(*x),
            _ => self.children().iter().for_each(|c| c.for_each_reg(f)),
        }
    }

    /// Visits every Reg in evaluation order, letting `f` replace it.
    pub fn rewrite_regs(&mut self, f: &mut impl FnMut(u16) -> Option<Expr>) {
        if let Reg(r) = self {
            if let Some(e) = f(*r) {
                *self = e;
            }
            return;
        }
        for c in self.children_mut() {
            c.rewrite_regs(f);
        }
    }

    pub fn negate(self) -> Expr {
        match self {
            Cmp(op, a, b) => Cmp(flip(op), a, b),
            And(a, b) => Or(bx(a.negate()), bx(b.negate())),
            Or(a, b) => And(bx(a.negate()), bx(b.negate())),
            Not(a) => *a,
            e => Not(bx(e)),
        }
    }
}

fn flip(op: &'static str) -> &'static str {
    match op {
        "==" => "!=", "!=" => "==", "<" => ">=", ">=" => "<", ">" => "<=", _ => ">",
    }
}

impl Stmt {
    /// expressions this statement evaluates, in order
    pub fn exprs(&self) -> Vec<&Expr> {
        match self {
            Stmt::Assign(_, e) | Stmt::Do(e) | Stmt::Throw(e) | Stmt::Monitor(_, e) | Stmt::Return(Some(e)) => vec![e],
            Stmt::Store(l, r) => l.children().into_iter().chain([r]).collect(),
            Stmt::Return(None) | Stmt::Nop => vec![],
        }
    }

    pub fn exprs_mut(&mut self) -> Vec<&mut Expr> {
        match self {
            Stmt::Assign(_, e) | Stmt::Do(e) | Stmt::Throw(e) | Stmt::Monitor(_, e) | Stmt::Return(Some(e)) => vec![e],
            Stmt::Store(l, r) => l.children_mut().into_iter().chain([r]).collect(),
            Stmt::Return(None) | Stmt::Nop => vec![],
        }
    }

    pub fn reads(&self, r: u16) -> usize {
        self.exprs().iter().map(|e| e.count_reg(r)).sum()
    }

    pub fn def(&self) -> Option<u16> {
        match self {
            Stmt::Assign(Reg(r), _) => Some(*r),
            _ => None,
        }
    }
}

const CMP: [&str; 6] = ["==", "!=", "<", ">=", ">", "<="];
const BIN: [&str; 11] = ["+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>", ">>>"];

fn bin_type(k: u8) -> char {
    match k % 32 {
        0..=10 => 'I',
        11..=21 => 'J',
        22..=26 => 'F',
        _ => 'D',
    }
}

fn bin_op(k: u8) -> &'static str {
    let k = k % 32;
    if k < 22 { BIN[(k % 11) as usize] } else { BIN[((k - 22) % 5) as usize] }
}

fn call_kind(op: u8) -> Call {
    match op {
        0xfa | 0xfb => Call::Poly,
        _ => [Call::Virtual, Call::Super, Call::Direct, Call::Static, Call::Interface][((op - 0x6e) % 6) as usize],
    }
}

/// Statements of insns first..=last, plus the terminator's condition (If) or key (Switch).
pub fn lower(dex: &Dex, insns: &[Insn], units: &[u8], first: usize, last: usize, term: &Term) -> R<(Vec<Stmt>, Option<Expr>)> {
    let mut out: Vec<Stmt> = Vec::with_capacity(last + 1 - first);
    let mut pending_new: HashMap<u16, (usize, String)> = HashMap::new();
    let mut cond = None;
    for k in first..=last {
        let i = &insns[k];
        let r = |n: usize| Reg(i.regs[n]);
        let args = || -> Vec<Expr> {
            if i.range { (0..i.nregs as u16).map(|x| Reg(i.regs[0] + x)).collect() } else { i.regs[..i.nregs as usize].iter().map(|&x| Reg(x)).collect() }
        };
        let assign = |e: Expr| Stmt::Assign(r(0), e);
        let s = match i.op {
            0x00 => continue,
            0x01..=0x09 => assign(r(1)),
            0x0a..=0x0c => {
                let prev = k.checked_sub(1).filter(|&p| p >= first).map(|p| insns[p].op);
                let folds = prev.is_some_and(|p| matches!(p, 0x24 | 0x25 | 0x6e..=0x72 | 0x74..=0x78 | 0xfa..=0xfd));
                match out.last() {
                    Some(Stmt::Do(_)) if folds => {
                        let Some(Stmt::Do(e)) = out.pop() else { unreachable!() };
                        assign(e)
                    }
                    _ => assign(Raw("<result>".into())),
                }
            }
            0x0d => assign(Caught),
            0x0e => Stmt::Return(None),
            0x0f..=0x11 => Stmt::Return(Some(r(0))),
            0x12..=0x15 => assign(Lit(i.lit, false)),
            0x16..=0x19 => assign(Lit(i.lit, true)),
            0x1a | 0x1b => assign(Str(dex.string(i.idx)?)),
            0x1c => assign(Class(dex.type_name(i.idx)?)),
            0x1d | 0x1e => Stmt::Monitor(i.op == 0x1d, r(0)),
            0x1f => assign(Cast(dex.type_name(i.idx)?, bx(r(0)))),
            0x20 => assign(InstanceOf(bx(r(1)), dex.type_name(i.idx)?)),
            0x21 => assign(ArrayLen(bx(r(1)))),
            0x22 => {
                let t = dex.type_name(i.idx)?;
                pending_new.insert(i.regs[0], (out.len(), t.clone()));
                // placeholder, replaced at the matching <init>
                assign(New(t, u32::MAX, vec![]))
            }
            0x23 => assign(NewArray(dex.type_name(i.idx)?, bx(r(1)))),
            0x24 | 0x25 => Stmt::Do(Filled(dex.type_name(i.idx)?, args())),
            0x26 => {
                let vals = array_payload(units, (i.off as i64 + i.lit) as usize)?;
                // `new T[n]` right before its data -> one array literal
                match out.last_mut() {
                    Some(Stmt::Assign(Reg(r0), NewArray(t, _))) if *r0 == i.regs[0] => {
                        let t = std::mem::take(t);
                        *out.last_mut().unwrap() = Stmt::Assign(Reg(*r0), ArrayLit(t, vals));
                        continue;
                    }
                    _ => Stmt::Do(Fill(bx(r(0)), vals)),
                }
            }
            0x27 => Stmt::Throw(r(0)),
            0x32..=0x37 => {
                cond = Some(Cmp(CMP[(i.op - 0x32) as usize], bx(r(0)), bx(r(1))));
                continue;
            }
            0x38..=0x3d => {
                cond = Some(Cmp(CMP[(i.op - 0x38) as usize], bx(r(0)), bx(Lit(0, false))));
                continue;
            }
            0x2b | 0x2c => {
                cond = Some(r(0));
                continue;
            }
            0x28..=0x2a => continue,
            0x2d..=0x31 => {
                let f = ["Float.compare", "Float.compare", "Double.compare", "Double.compare", "Long.compare"][(i.op - 0x2d) as usize];
                assign(Compare(f, bx(r(1)), bx(r(2))))
            }
            0x44..=0x4a => assign(ArrayGet(bx(r(1)), bx(r(2)))),
            0x4b..=0x51 => Stmt::Store(ArrayGet(bx(r(1)), bx(r(2))), r(0)),
            0x52..=0x58 => assign(Field(Some(bx(r(1))), i.idx)),
            0x59..=0x5f => Stmt::Store(Field(Some(bx(r(1))), i.idx), r(0)),
            0x60..=0x66 => assign(Field(None, i.idx)),
            0x67..=0x6d => Stmt::Store(Field(None, i.idx), r(0)),
            0x6e..=0x72 | 0x74..=0x78 | 0xfa | 0xfb => {
                let kind = call_kind(i.op);
                // a long/double argument fills two registers; keep only the first
                let mut a = args();
                if let (false, Ok((_, _, p))) = (kind == Call::Poly, dex.method_parts(i.idx)) {
                    let mut k = (kind != Call::Static) as usize;
                    for t in dex.proto_parts(p).map(|p| p.1).unwrap_or_default() {
                        if t == "J" || t == "D" {
                            if k + 1 < a.len() {
                                a.remove(k + 1);
                            }
                        }
                        k += 1;
                    }
                }
                let ctor = kind == Call::Direct && dex.method_parts(i.idx)?.1 == "<init>";
                // `new T` + `T.<init>(v, ...)` -> `v = new T(...)` at the <init>, after its args are computed
                if let (true, Some(&Reg(recv))) = (ctor, a.first()) {
                    if let Some((at, t)) = pending_new.remove(&recv) {
                        out[at] = Stmt::Nop;
                        out.push(Stmt::Assign(Reg(recv), New(t, i.idx, a[1..].to_vec())));
                        continue;
                    }
                }
                Stmt::Do(Invoke(kind, i.idx, a))
            }
            0xfc | 0xfd => Stmt::Do(Custom(i.idx, args())),
            0xfe => assign(Raw(format!("method_handle#{}", i.idx))),
            0xff => assign(Raw(format!("method_type(\"{}\")", dex.proto(i.idx)?))),
            0x7b..=0x8f => {
                const UN: [(&str, char); 21] = [
                    ("-", 'I'), ("~", 'I'), ("-", 'J'), ("~", 'J'), ("-", 'F'), ("-", 'D'), ("(long) ", 'J'), ("(float) ", 'F'),
                    ("(double) ", 'D'), ("(int) ", 'I'), ("(float) ", 'F'), ("(double) ", 'D'), ("(int) ", 'I'), ("(long) ", 'J'),
                    ("(double) ", 'D'), ("(int) ", 'I'), ("(long) ", 'J'), ("(float) ", 'F'), ("(byte) ", 'B'), ("(char) ", 'C'), ("(short) ", 'S'),
                ];
                let (p, t) = UN[(i.op - 0x7b) as usize];
                assign(Un(p, t, bx(r(1))))
            }
            0x90..=0xaf => assign(Bin(bin_op(i.op - 0x90), bin_type(i.op - 0x90), bx(r(1)), bx(r(2)))),
            0xb0..=0xcf => assign(Bin(bin_op(i.op - 0xb0), bin_type(i.op - 0xb0), bx(r(0)), bx(r(1)))),
            0xd0..=0xe2 => {
                let k = if i.op <= 0xd7 { i.op - 0xd0 } else { i.op - 0xd8 } as usize;
                let lit = bx(Lit(i.lit, false));
                if k == 1 { assign(Bin("-", 'I', lit, bx(r(1)))) } else { assign(Bin(BIN[k], 'I', bx(r(1)), lit)) }
            }
            op => return Err(format!("unhandled opcode {op:#x}")),
        };
        out.push(s);
    }
    // an unmatched `new T` keeps its placeholder (ctor u32::MAX); fold_split_new joins it to its
    // constructor call in another block once variables are known
    let _ = pending_new;
    out.retain(|s| *s != Stmt::Nop);
    if !matches!(term, Term::If { .. } | Term::Switch { .. }) {
        cond = None;
    }
    Ok((out, cond))
}

/// fill-array-data payload at code unit `p`: element values, sign-extended to their width
fn array_payload(units: &[u8], p: usize) -> R<Vec<i64>> {
    let b = |o: usize, n: usize| units.get(p * 2 + o..p * 2 + o + n).ok_or_else(|| "array payload past end".to_string());
    let width = u16::from_le_bytes(b(2, 2)?.try_into().unwrap()) as usize;
    let count = u32::from_le_bytes(b(4, 4)?.try_into().unwrap()) as usize;
    if !matches!(width, 1 | 2 | 4 | 8) || count > units.len() {
        return Err(format!("bad array payload (width {width}, count {count})"));
    }
    let data = b(8, width * count)?;
    Ok(data
        .chunks_exact(width)
        .map(|c| match width {
            1 => c[0] as i8 as i64,
            2 => i16::from_le_bytes([c[0], c[1]]) as i64,
            4 => i32::from_le_bytes(c.try_into().unwrap()) as i64,
            _ => i64::from_le_bytes(c.try_into().unwrap()),
        })
        .collect())
}

/// `I` -> `int`, `Ljava/lang/String;` -> `java.lang.String`, `[I` -> `int[]`
pub fn jtype(desc: &str) -> String {
    if let Some(inner) = desc.strip_prefix('[') {
        return jtype(inner) + "[]";
    }
    match desc {
        "V" => "void", "Z" => "boolean", "B" => "byte", "S" => "short", "C" => "char",
        "I" => "int", "J" => "long", "F" => "float", "D" => "double",
        _ => return dex::java_name(desc),
    }
    .into()
}

/// short type name: `Lcom/a/Outer$Inner;` -> `Inner`, `[I` -> `int[]`
pub fn simple(desc: &str) -> String {
    let j = jtype(desc);
    let dims = j.matches("[]").count();
    let base = j.trim_end_matches("[]");
    let short = base.rsplit(['.', '$']).next().unwrap_or(base);
    // anonymous classes (`Outer$2`) have no usable short name
    if short.starts_with(|c: char| c.is_ascii_digit()) {
        return format!("AnonymousClass{short}") + &"[]".repeat(dims);
    }
    short.to_string() + &"[]".repeat(dims)
}

const KEYWORDS: &[&str] = &[
    "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const", "continue", "default", "do",
    "double", "else", "enum", "extends", "final", "finally", "float", "for", "goto", "if", "implements", "import", "instanceof",
    "int", "interface", "long", "native", "new", "package", "private", "protected", "public", "return", "short", "static",
    "strictfp", "super", "switch", "synchronized", "this", "throw", "throws", "transient", "try", "void", "volatile", "while",
    "true", "false", "null", "var", "record", "yield",
];

/// variable name from a type, JADX-style: `WorldScreen` -> `worldScreen`, `int` -> `i`
pub fn name_for(ty: Option<&str>) -> String {
    let Some(t) = ty else { return "obj".into() };
    match t {
        "I" => return "i".into(), "J" => return "j".into(), "Z" => return "z".into(), "F" => return "f".into(),
        "D" => return "d".into(), "C" => return "c".into(), "B" => return "b".into(), "S" => return "s".into(),
        "Ljava/lang/String;" => return "str".into(), "Ljava/lang/Object;" => return "obj".into(),
        _ => {}
    }
    if let Some(inner) = t.strip_prefix('[') {
        return name_for(Some(inner)) + "Arr";
    }
    let s = simple(t);
    let s: String = s.chars().filter(|c| c.is_alphanumeric() || *c == '_').collect();
    let mut cs = s.chars();
    let n = match cs.next() {
        Some(c) if c.is_ascii_digit() => format!("v{s}"),
        Some(c) => c.to_lowercase().chain(cs).collect(),
        None => "obj".into(),
    };
    if KEYWORDS.contains(&n.as_str()) { n + "Val" } else { n }
}

/// Per-method variable table; indices are definition ids.
pub struct Vars {
    pub root: Vec<usize>,
    /// definition counts per root, excluding parameters
    pub defs: Vec<usize>,
    pub param: Vec<bool>,
    pub ty: Vec<Option<String>>,
    pub name: Vec<String>,
}

pub struct Ctx<'a> {
    pub dex: &'a Dex<'a>,
    pub class: &'a str,
    pub ret: String,
    pub vars: Option<Vars>,
}

impl<'a> Ctx<'a> {
    fn var_ty(&self, d: usize) -> Option<String> {
        self.vars.as_ref().and_then(|v| v.ty[v.root[d]].clone())
    }

    pub fn type_of(&self, e: &Expr) -> Option<String> {
        let d = self.dex;
        match e {
            Var(v) => self.var_ty(*v),
            Str(_) => Some("Ljava/lang/String;".into()),
            Class(_) => Some("Ljava/lang/Class;".into()),
            Caught => Some("Ljava/lang/Throwable;".into()),
            Field(_, f) => d.field_parts(*f).ok().map(|p| p.1),
            Invoke(_, m, _) => d.method_parts(*m).ok().and_then(|(_, _, p)| d.proto_parts(p).ok()).map(|p| p.0).filter(|t| t != "V"),
            New(t, ..) | NewArray(t, _) | Filled(t, _) | Cast(t, _) | ArrayLit(t, _) => Some(t.clone()),
            Bin(_, t, ..) | Un(_, t, _) => Some(t.to_string()),
            InstanceOf(..) | Cmp(..) | And(..) | Or(..) | Not(_) => Some("Z".into()),
            ArrayLen(_) | Compare(..) => Some("I".into()),
            Concat(_) => Some("Ljava/lang/String;".into()),
            ArrayGet(a, _) => self.type_of(a).and_then(|t| t.strip_prefix('[').map(str::to_string)),
            _ => None,
        }
    }

    /// Types and names for every variable. `params` = (def id, descriptor, fixed name).
    pub fn assign_vars(&mut self, mut vars: Vars, blocks: &[(Vec<Stmt>, Option<Expr>)], params: &[(usize, String, Option<String>)]) {
        for (d, t, _) in params {
            let r = vars.root[*d];
            vars.ty[r] = Some(t.clone());
        }
        self.vars = Some(vars);
        // definitions first, then hints from how values are used; repeat so copies pick up types
        for _ in 0..3 {
            for (stmts, cond) in blocks {
                for s in stmts {
                    if let Stmt::Assign(Var(d), e) = s {
                        if self.var_ty(*d).is_none() {
                            if let Some(t) = self.type_of(e) {
                                self.set_ty(*d, t);
                            }
                        }
                    }
                    self.hint_stmt(s);
                }
                if let Some(c) = cond {
                    self.hint(c, None);
                }
            }
        }
        let v = self.vars.as_mut().unwrap();
        let mut used: HashMap<String, usize> = HashMap::new();
        for (d, _, fixed) in params {
            let r = v.root[*d];
            let base = fixed.clone().unwrap_or_else(|| name_for(v.ty[r].as_deref()));
            let k = used.entry(base.clone()).or_default();
            *k += 1;
            v.name[r] = if *k == 1 { base } else { format!("{base}{k}") };
        }
        for r in 0..v.root.len() {
            if v.root[r] != r || !v.name[r].is_empty() {
                continue;
            }
            if v.ty[r].is_none() {
                v.ty[r] = Some("I".into()); // only literals flowed in
            }
            let base = name_for(v.ty[r].as_deref());
            let k = used.entry(base.clone()).or_default();
            *k += 1;
            v.name[r] = if *k == 1 { base } else { format!("{base}{k}") };
        }
    }

    fn set_ty(&mut self, d: usize, t: String) {
        let v = self.vars.as_mut().unwrap();
        let r = v.root[d];
        if v.ty[r].is_none() {
            v.ty[r] = Some(t);
        }
    }

    fn hint_stmt(&mut self, s: &Stmt) {
        match s {
            Stmt::Store(l, r) => {
                let t = self.type_of(l);
                for c in l.children() {
                    self.hint(c, None);
                }
                self.hint(r, t);
            }
            Stmt::Return(Some(e)) => {
                let t = Some(self.ret.clone());
                self.hint(e, t);
            }
            _ => {
                for e in s.exprs() {
                    self.hint(e, None);
                }
            }
        }
    }

    /// propagate the type a context expects into variables of unknown type
    fn hint(&mut self, e: &Expr, want: Option<String>) {
        match e {
            Var(d) => {
                if let Some(t) = want {
                    self.set_ty(*d, t);
                }
            }
            Invoke(kind, m, args) => {
                let params = self.dex.method_parts(*m).ok().and_then(|(_, _, p)| self.dex.proto_parts(p).ok()).map(|p| p.1).unwrap_or_default();
                let skip = (*kind != Call::Static) as usize;
                for (k, a) in args.iter().enumerate() {
                    let t = k.checked_sub(skip).and_then(|k| params.get(k).cloned());
                    self.hint(a, t);
                }
            }
            New(_, m, args) => {
                let params = self.dex.method_parts(*m).ok().and_then(|(_, _, p)| self.dex.proto_parts(p).ok()).map(|p| p.1).unwrap_or_default();
                for (a, t) in args.iter().zip(params.into_iter().map(Some).chain(std::iter::repeat(None))) {
                    self.hint(a, t);
                }
            }
            Cmp(_, a, b) => {
                let (ta, tb) = (self.type_of(a), self.type_of(b));
                self.hint(a, tb);
                self.hint(b, ta);
            }
            ArrayGet(a, i) => {
                self.hint(a, None);
                self.hint(i, Some("I".into()));
            }
            _ => {
                for c in e.children() {
                    self.hint(c, None);
                }
            }
        }
    }

    pub fn var_name(&self, d: usize) -> String {
        let v = self.vars.as_ref().unwrap();
        v.name[v.root[d]].clone()
    }

    fn atom(&self, e: &Expr) -> String {
        let s = self.expr(e, None);
        if matches!(e, Bin(..) | Cmp(..) | And(..) | Or(..) | InstanceOf(..) | Cast(..) | Un(..)) { format!("({s})") } else { s }
    }

    fn owner(&self, class: &str) -> Option<String> {
        (class != self.class).then(|| type_ref(class))
    }

    fn call_args(&self, args: &[Expr], params: &[String]) -> String {
        let v: Vec<String> = args.iter().enumerate().map(|(k, a)| self.expr(a, params.get(k).map(String::as_str))).collect();
        v.join(", ")
    }

    pub fn expr(&self, e: &Expr, want: Option<&str>) -> String {
        let d = self.dex;
        match e {
            Reg(r) => format!("v{r}"),
            Var(v) => self.var_name(*v),
            Lit(v, wide) => lit(*v, *wide, want),
            Str(s) => java_string(s),
            Class(t) => format!("{}.class", type_ref(t)),
            Caught => "<caught exception>".into(),
            Field(obj, f) => {
                let Ok((c, ty, name)) = d.field_parts(*f) else { return format!("field#{f}") };
                // non-capturing lambda singleton
                if obj.is_none() && ty == c {
                    if let Some(l) = self.lambda(&c, &[]) {
                        return l;
                    }
                }
                match obj {
                    Some(o) => {
                        let recv = self.atom(o);
                        // synthetic capture field of an inline anonymous class
                        if recv == "this" {
                            if let Some(t) = crate::java::capture(*f) {
                                return t;
                            }
                        }
                        format!("{recv}.{}", crate::deobf::field(&c, &name, &ty).unwrap_or(name))
                    }
                    None => {
                        let name = crate::deobf::field(&c, &name, &ty).unwrap_or(name);
                        self.owner(&c).map_or(name.clone(), |o| format!("{o}.{name}"))
                    }
                }
            }
            Invoke(kind, m, args) => {
                let Ok((c, name, p)) = d.method_parts(*m) else { return format!("method#{m}") };
                let name = crate::deobf::method(&c, &name).unwrap_or(name);
                let params = d.proto_parts(p).map(|p| p.1).unwrap_or_default();
                if *kind == Call::Static || args.is_empty() {
                    let a = self.call_args(args, &params);
                    let call = self.owner(&c).map_or(format!("{name}({a})"), |o| format!("{o}.{name}({a})"));
                    // string decryptor on constants: show what it returns
                    return match (*kind == Call::Static).then(|| crate::re::decrypt_call(d, *m, args)).flatten() {
                        Some(p) => format!("{call} /* = {} */", java_string(&p).replace("*/", "* /")),
                        None => call,
                    };
                }
                let a = self.call_args(&args[1..], &params);
                let recv = self.atom(&args[0]);
                if name == "<init>" && recv == "this" {
                    return format!("{}({a})", if c == self.class { "this" } else { "super" });
                }
                match kind {
                    Call::Super => format!("super.{name}({a})"),
                    _ if recv == "this" => format!("{name}({a})"),
                    _ => format!("{recv}.{name}({a})"),
                }
            }
            New(t, u32::MAX, _) => format!("new {}(/* constructor called later */)", type_ref(t)),
            New(t, m, args) => {
                if let Some(a) = crate::java::anon_new(self, t, args) {
                    return a;
                }
                if let Some(l) = self.lambda(t, args) {
                    return l;
                }
                let params = d.method_parts(*m).ok().and_then(|(_, _, p)| d.proto_parts(p).ok()).map(|p| p.1).unwrap_or_default();
                format!("new {}({})", type_ref(t), self.call_args(args, &params))
            }
            NewArray(t, n) => {
                let elem = type_ref(t.strip_prefix('[').unwrap_or(t));
                let (base, dims) = (elem.trim_end_matches("[]"), elem.matches("[]").count());
                format!("new {base}[{}]{}", self.expr(n, Some("I")), "[]".repeat(dims))
            }
            Filled(t, args) => {
                let elem = t.strip_prefix('[').unwrap_or(t);
                let v: Vec<String> = args.iter().map(|a| self.expr(a, Some(elem))).collect();
                format!("new {}{{{}}}", type_ref(t), v.join(", "))
            }
            Bin("+", t, a, b) if matches!(**b, Lit(v, _) if v < 0 && v != i64::MIN) => {
                let Lit(v, w) = **b else { unreachable!() };
                let t = t.to_string();
                format!("{} - {}", self.operand(a, Some(&t)), self.operand(&Lit(-v, w), Some(&t)))
            }
            Bin(op, t, a, b) => {
                let t = t.to_string();
                format!("{} {op} {}", self.operand(a, Some(&t)), self.operand(b, Some(&t)))
            }
            Un(p, _, a) => format!("{p}{}", self.atom(a)),
            Cast(t, a) => format!("({}) {}", type_ref(t), self.atom(a)),
            InstanceOf(a, t) => format!("{} instanceof {}", self.atom(a), type_ref(t)),
            ArrayGet(a, i) => format!("{}[{}]", self.atom(a), self.expr(i, Some("I"))),
            ArrayLen(a) => format!("{}.length", self.atom(a)),
            Compare(f, a, b) => format!("{f}({}, {})", self.expr(a, None), self.expr(b, None)),
            Cmp(op, a, b) => {
                // Float.compare(x, y) < 0  ->  x < y
                if let (Compare(_, x, y), Lit(0, _)) = (&**a, &**b) {
                    return format!("{} {op} {}", self.expr(x, None), self.expr(y, None));
                }
                let (ta, tb) = (self.type_of(a), self.type_of(b));
                if matches!(**b, Lit(0, _)) && ta.as_deref() == Some("Z") {
                    return if *op == "==" { format!("!{}", self.atom(a)) } else { self.expr(a, None) };
                }
                format!("{} {op} {}", self.operand(a, tb.as_deref()), self.operand(b, ta.as_deref()))
            }
            And(a, b) => {
                let p = |x: &Expr| if matches!(x, Or(..)) { format!("({})", self.expr(x, None)) } else { self.expr(x, None) };
                format!("{} && {}", p(a), p(b))
            }
            Or(a, b) => format!("{} || {}", self.expr(a, None), self.expr(b, None)),
            Not(a) => format!("!{}", self.atom(a)),
            // shortcut: lambdas/method handles shown raw, decoded with call sites later
            Custom(cs, args) => format!("invokeCustom#{cs}({})", self.call_args(args, &[])),
            ArrayLit(t, vals) => {
                let elem = t.strip_prefix('[').unwrap_or("I");
                let v: Vec<String> = vals.iter().map(|x| lit(*x, false, Some(elem))).collect();
                format!("new {}{{{}}}", type_ref(t), v.join(", "))
            }
            Fill(a, vals) => {
                let t = self.type_of(a).filter(|t| t.starts_with('[')).unwrap_or_else(|| "[I".into());
                format!("{} = {}", self.expr(a, None), self.expr(&ArrayLit(t, vals.clone()), None))
            }
            Concat(parts) => {
                let is_str = |e: &Expr| self.type_of(e).as_deref() == Some("Ljava/lang/String;");
                let mut v: Vec<String> = parts.iter().map(|(e, t)| self.operand(e, Some(t))).collect();
                // `a + b` with no String among the first two would add numbers, not concatenate
                if !parts.iter().take(2).any(|(e, _)| is_str(e)) {
                    v.insert(0, "\"\"".into());
                }
                v.join(" + ")
            }
            Raw(s) => s.clone(),
        }
    }

    /// `(a, b) -> body` for a compiler-generated lambda class whose single method is one statement.
    fn lambda(&self, class: &str, captured: &[Expr]) -> Option<String> {
        let d = self.dex;
        let c = d.find_class(class)?;
        let def = d.class_def(c).ok()?;
        // synthetic + final, implementing exactly one interface
        // captured values are computed at creation; inside the body they would look lazy
        if def.access & 0x1010 != 0x1010 || def.interfaces.len() != 1 || !captured.iter().all(Expr::is_pure) {
            return None;
        }
        let data = d.class_data(c).ok()?;
        let mut impls = data.methods.iter().filter(|m| m.code.is_some() && d.method_parts(m.method_idx).is_ok_and(|p| !p.1.starts_with('<')));
        let (m, None) = (impls.next()?, impls.next()) else { return None };
        let code = m.code.as_ref()?;
        let (_, _, proto) = d.method_parts(m.method_idx).ok()?;
        let (ret, params) = d.proto_parts(proto).ok()?;
        let insns = crate::bytecode::decode(code.insns).ok()?;
        let cfg = crate::cfg::build(&insns, code.insns, &code.tries).ok()?;
        if cfg.blocks.len() != 1 {
            return None;
        }
        let mut bir = vec![lower(d, &insns, code.insns, 0, cfg.blocks[0].last, &cfg.blocks[0].term).ok()?];
        crate::opt::inline(&cfg, &mut bir, code.registers as usize);
        let body = match bir[0].0.as_slice() {
            [Stmt::Return(Some(e))] | [Stmt::Do(e), Stmt::Return(None)] => e.clone(),
            _ => return None,
        };
        // instance fields in order are the captured values
        let fields: Vec<u32> = data.fields.iter().filter(|f| f.1 & 0x8 == 0).map(|f| f.0).collect();
        let this = code.registers - code.ins;
        let mut names = Vec::new();
        let mut regs: HashMap<u16, String> = HashMap::new();
        let mut r = this + 1;
        let mut used: HashMap<String, usize> = HashMap::new();
        for p in &params {
            let base = name_for(Some(p));
            let k = used.entry(base.clone()).or_default();
            *k += 1;
            let n = if *k == 1 { base } else { format!("{base}{k}") };
            regs.insert(r, n.clone());
            names.push(n);
            r += if p == "J" || p == "D" { 2 } else { 1 };
        }
        let mut ok = true;
        fn subst(e: &mut Expr, this: u16, fields: &[u32], cap: &[String], regs: &HashMap<u16, String>, ok: &mut bool) {
            match e {
                Field(Some(o), f) if **o == Reg(this) => match fields.iter().position(|x| x == f).and_then(|k| cap.get(k)) {
                    Some(s) => *e = Raw(s.clone()),
                    None => *ok = false,
                },
                Reg(x) => match regs.get(x) {
                    Some(n) => *e = Raw(n.clone()),
                    None => *ok = false,
                },
                _ => e.children_mut().into_iter().for_each(|c| subst(c, this, fields, cap, regs, ok)),
            }
        }
        let cap: Vec<String> = captured.iter().map(|a| self.expr(a, None)).collect();
        let mut body = body;
        subst(&mut body, this, &fields, &cap, &regs, &mut ok);
        if !ok {
            return None;
        }
        let inner = Ctx { dex: d, class: self.class, ret, vars: None };
        Some(format!("({}) -> {}", names.join(", "), inner.expr(&body, None)))
    }

    fn operand(&self, e: &Expr, t: Option<&str>) -> String {
        let s = self.expr(e, t);
        if matches!(e, Bin(..) | Cmp(..) | And(..) | Or(..) | InstanceOf(..)) { format!("({s})") } else { s }
    }

    pub fn stmt(&self, s: &Stmt) -> String {
        match s {
            Stmt::Assign(Var(d), e) => {
                let v = self.vars.as_ref().unwrap();
                let r = v.root[*d];
                let name = &v.name[r];
                let ty = v.ty[r].clone();
                if v.defs[r] == 1 && !v.param[r] {
                    let t = ty.as_deref().map_or("Object".into(), type_ref);
                    return format!("{t} {name} = {};", self.expr(e, ty.as_deref()));
                }
                if let Bin(op, _, a, b) = e {
                    if matches!(&**a, Var(x) if v.root[*x] == r) {
                        return match (*op, &**b) {
                            ("+", Lit(1, _)) | ("-", Lit(-1, _)) => format!("{name}++;"),
                            ("-", Lit(1, _)) | ("+", Lit(-1, _)) => format!("{name}--;"),
                            ("+", Lit(v, w)) if *v < 0 && *v != i64::MIN => format!("{name} -= {};", self.expr(&Lit(-v, *w), ty.as_deref())),
                            _ => format!("{name} {op}= {};", self.expr(b, ty.as_deref())),
                        };
                    }
                }
                format!("{name} = {};", self.expr(e, ty.as_deref()))
            }
            Stmt::Assign(t, e) => format!("{} = {};", self.expr(t, None), self.expr(e, None)),
            Stmt::Store(l, r) => {
                // an assignment target is always the plain field, never a lambda/capture stand-in
                let target = match l {
                    Field(None, f) => match self.dex.field_parts(*f) {
                        Ok((c, ty, name)) => {
                            let name = crate::deobf::field(&c, &name, &ty).unwrap_or(name);
                            self.owner(&c).map_or(name.clone(), |o| format!("{o}.{name}"))
                        }
                        Err(_) => self.expr(l, None),
                    },
                    _ => self.expr(l, None),
                };
                format!("{target} = {};", self.expr(r, self.type_of(l).as_deref()))
            }
            Stmt::Do(e) => format!("{};", self.expr(e, None)),
            Stmt::Return(None) => "return;".into(),
            Stmt::Return(Some(e)) => format!("return {};", self.expr(e, Some(&self.ret))),
            Stmt::Throw(e) => format!("throw {};", self.expr(e, None)),
            Stmt::Monitor(enter, e) => format!("monitor{}({});", if *enter { "Enter" } else { "Exit" }, self.expr(e, None)),
            Stmt::Nop => String::new(),
        }
    }
}

/// A variable assigned once with a literal is replaced by the literal at every use; each use then
/// prints the literal in its own context's type (`0` vs `null` vs `false`).
pub fn propagate_constants(bir: &mut [(Vec<Stmt>, Option<Expr>)], vars: &Vars) {
    let mut consts: HashMap<usize, Expr> = HashMap::new();
    for (stmts, _) in bir.iter() {
        for st in stmts {
            if let Stmt::Assign(Var(d), e @ (Lit(..) | Str(_) | Class(_))) = st {
                let r = vars.root[*d];
                if vars.defs[r] == 1 && !vars.param[r] {
                    consts.insert(r, e.clone());
                }
            }
        }
    }
    if consts.is_empty() {
        return;
    }
    fn sub(e: &mut Expr, vars: &Vars, consts: &HashMap<usize, Expr>) {
        if let Var(d) = e {
            if let Some(v) = consts.get(&vars.root[*d]) {
                *e = v.clone();
            }
            return;
        }
        for c in e.children_mut() {
            sub(c, vars, consts);
        }
    }
    for (stmts, cond) in bir.iter_mut() {
        stmts.retain(|st| !matches!(st, Stmt::Assign(Var(d), _) if consts.contains_key(&vars.root[*d])));
        for st in stmts.iter_mut() {
            for e in st.exprs_mut() {
                sub(e, vars, &consts);
            }
        }
        if let Some(c) = cond {
            sub(c, vars, &consts);
        }
    }
}

/// `x = new T` and its `x.<init>(args)` in different statements or blocks -> `x = new T(args)` at
/// the call, where the object really starts to exist. A placeholder in the call's own block wins,
/// then one whose block dominates the call, then a lone placeholder. A copy `y = x` made before
/// the constructor ran (`y.<init>(..)`) moves to just after the new `x = new T(..)`.
pub fn fold_split_new(dex: &Dex, cfg: &crate::cfg::Cfg, bir: &mut [(Vec<Stmt>, Option<Expr>)], vars: &Vars) {
    // root -> placeholders (block, stmt, def, type)
    let mut pending: HashMap<usize, Vec<(usize, usize, usize, String)>> = HashMap::new();
    for (b, (stmts, _)) in bir.iter().enumerate() {
        for (k, st) in stmts.iter().enumerate() {
            if let Stmt::Assign(Var(d), New(t, u32::MAX, _)) = st {
                let r = vars.root[*d];
                if !vars.param[r] {
                    pending.entry(r).or_default().push((b, k, *d, t.clone()));
                }
            }
        }
    }
    if pending.is_empty() {
        return;
    }
    // copies of a placeholder: copy root -> (placeholder root, block, stmt, the copy itself)
    let mut copies: HashMap<usize, (usize, usize, usize, Stmt)> = HashMap::new();
    for (b, (stmts, _)) in bir.iter().enumerate() {
        for (k, st) in stmts.iter().enumerate() {
            if let Stmt::Assign(Var(y), Var(x)) = st {
                let (ry, rx) = (vars.root[*y], vars.root[*x]);
                if pending.contains_key(&rx) && ry != rx && vars.defs[ry] == 1 {
                    copies.insert(ry, (rx, b, k, st.clone()));
                }
            }
        }
    }
    let mut remove = Vec::new();
    // (block, stmt) -> statements replacing it
    let mut replace: HashMap<(usize, usize), Vec<Stmt>> = HashMap::new();
    for (blk, (stmts, _)) in bir.iter().enumerate() {
        for (k, st) in stmts.iter().enumerate() {
            let Stmt::Do(Invoke(Call::Direct, m, a)) = st else { continue };
            let Some(Var(x)) = a.first() else { continue };
            let mut root = vars.root[*x];
            let mut copy = None;
            if !pending.contains_key(&root) {
                let Some(c) = copies.get(&root) else { continue };
                root = c.0;
                copy = Some(c.clone());
            }
            let Some(cands) = pending.get(&root) else { continue };
            if !dex.method_parts(*m).is_ok_and(|p| p.1 == "<init>") {
                continue;
            }
            // same block first, then the one whose block every path to the call goes through
            let pick = cands
                .iter()
                .rposition(|c| c.0 == blk && c.1 < k)
                .or_else(|| cands.iter().position(|c| c.0 != blk && cfg.dominates(c.0, blk)))
                .or((cands.len() == 1).then_some(0));
            let Some(pick) = pick else { continue };
            // kept: a `new T` before a branch is constructed once in each arm
            let (b, at, d, t) = cands[pick].clone();
            let mut with = vec![Stmt::Assign(Var(d), New(t, *m, a[1..].to_vec()))];
            if let Some((_, cb, ck, cst)) = copy {
                remove.push((cb, ck));
                with.push(cst);
            }
            replace.insert((blk, k), with);
            if !remove.contains(&(b, at)) {
                remove.push((b, at));
            }
        }
    }
    for (b, k) in remove {
        bir[b].0[k] = Stmt::Nop;
    }
    // later slots first, so splicing two statements in doesn't shift ones still to do
    let mut replace: Vec<_> = replace.into_iter().collect();
    replace.sort_by_key(|((b, k), _)| (*b, std::cmp::Reverse(*k)));
    for ((b, k), with) in replace {
        bir[b].0.splice(k..k + 1, with);
    }
    for (stmts, _) in bir.iter_mut() {
        stmts.retain(|s| *s != Stmt::Nop);
    }
}

const BUILDERS: [&str; 2] = ["Ljava/lang/StringBuilder;", "Ljava/lang/StringBuffer;"];

/// `sb = new StringBuilder(x); sb.append(a); ...; f(sb.toString())` -> `f(x + a + ...)`,
/// when the builder variable is used nowhere else.
pub fn fold_concat(dex: &Dex, bir: &mut [(Vec<Stmt>, Option<Expr>)], vars: &Vars) {
    let mut uses = vec![0usize; vars.root.len()];
    fn count(e: &Expr, vars: &Vars, uses: &mut [usize]) {
        if let Var(d) = e {
            uses[vars.root[*d]] += 1;
        }
        e.children().into_iter().for_each(|c| count(c, vars, uses));
    }
    for (stmts, cond) in bir.iter() {
        for x in stmts.iter().flat_map(|s| s.exprs()).chain(cond.iter()) {
            count(x, vars, &mut uses);
        }
    }
    let method = |m: u32| dex.method_parts(m).ok().and_then(|(c, n, p)| Some((c, n, dex.proto_parts(p).ok()?.1)));
    for (stmts, _) in bir.iter_mut() {
        let mut i = 0;
        while i < stmts.len() {
            let Stmt::Assign(Var(d), New(t, ctor, args)) = &stmts[i] else { i += 1; continue };
            let r = vars.root[*d];
            if !BUILDERS.contains(&t.as_str()) || vars.defs[r] != 1 || vars.param[r] {
                i += 1;
                continue;
            }
            let mut parts: Vec<(Expr, String)> = Vec::new();
            match (method(*ctor), args.first()) {
                (Some((_, _, p)), Some(a)) if p.first().is_some_and(|t| t != "I") => parts.push((a.clone(), p[0].clone())),
                _ => {}
            }
            let mut j = i + 1;
            while let Some(Stmt::Do(Invoke(Call::Virtual, m, a))) = stmts.get(j) {
                let Some((c, n, p)) = method(*m) else { break };
                if !(BUILDERS.contains(&c.as_str()) && n == "append" && a.len() == 2 && matches!(a[0], Var(x) if vars.root[x] == r)) {
                    break;
                }
                parts.push((a[1].clone(), p.first().cloned().unwrap_or_default()));
                j += 1;
            }
            // the builder must be used exactly: its appends plus one toString() in stmts[j]
            let to_string = |e: &Expr| matches!(e, Invoke(Call::Virtual, m, a) if a.len() == 1 && matches!(a[0], Var(x) if vars.root[x] == r) && method(*m).is_some_and(|(_, n, _)| n == "toString"));
            if j >= stmts.len() || uses[r] != j - i {
                i += 1;
                continue;
            }
            let mut done = false;
            let concat = Concat(parts);
            fn replace(e: &mut Expr, f: &dyn Fn(&Expr) -> bool, with: &Expr, done: &mut bool) {
                if !*done && f(e) {
                    *e = with.clone();
                    *done = true;
                    return;
                }
                for c in e.children_mut() {
                    replace(c, f, with, done);
                }
            }
            for e in stmts[j].exprs_mut() {
                replace(e, &to_string, &concat, &mut done);
            }
            if done {
                stmts.drain(i..j);
            } else {
                i += 1;
            }
        }
    }
}

fn lit(v: i64, wide: bool, want: Option<&str>) -> String {
    match want.and_then(|w| w.chars().next()) {
        Some('Z') if v == 0 || v == 1 => (if v == 0 { "false" } else { "true" }).into(),
        Some('L' | '[') if v == 0 => "null".into(),
        Some('F') => float(f32::from_bits(v as u32) as f64, "f", "Float"),
        Some('D') => float(f64::from_bits(v as u64), "", "Double"),
        Some('C') if (0x20..0x7f).contains(&v) => format!("{:?}", char::from(v as u8)).replace('"', "\\\""),
        Some('J') => format!("{v}L"),
        _ if wide => format!("{v}L"),
        _ => v.to_string(),
    }
}

fn float(x: f64, suffix: &str, class: &str) -> String {
    if x.is_nan() {
        format!("{class}.NaN")
    } else if x.is_infinite() {
        format!("{class}.{}_INFINITY", if x > 0.0 { "POSITIVE" } else { "NEGATIVE" })
    } else {
        format!("{x:?}{suffix}")
    }
}

pub fn java_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out += "\\\"",
            '\\' => out += "\\\\",
            '\n' => out += "\\n",
            '\r' => out += "\\r",
            '\t' => out += "\\t",
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out += &format!("\\u{u:04x}");
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(jtype("[[Ljava/lang/String;"), "java.lang.String[][]");
        assert_eq!(simple("Lcom/a/Outer$Inner;"), "Inner");
        assert_eq!(simple("[Lcom/a/B;"), "B[]");
        assert_eq!(name_for(Some("Lcom/x/WorldScreen;")), "worldScreen");
        assert_eq!(name_for(Some("Ljava/lang/Boolean;")), "booleanVal");
        assert_eq!(name_for(Some("[I")), "iArr");
        assert_eq!(lit(0, false, Some("Ljava/lang/Object;")), "null");
        assert_eq!(lit(1, false, Some("Z")), "true");
        assert_eq!(lit(0x3f800000, false, Some("F")), "1.0f");
        assert_eq!(java_string("a\"\n\u{e9}"), "\"a\\\"\\n\\u00e9\"");
        let c = Cmp("<", bx(Reg(0)), bx(Reg(1)));
        assert_eq!(And(bx(c.clone()), bx(Reg(2))).negate(), Or(bx(Cmp(">=", bx(Reg(0)), bx(Reg(1)))), bx(Not(bx(Reg(2))))));
        assert_eq!(bin_op(0xaf - 0x90), "%");
        assert_eq!(bin_type(0xaf - 0x90), 'D');
    }
}
