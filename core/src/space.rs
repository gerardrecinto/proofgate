//! The request space as hyper-rectangles. A cube holds one bitmask of allowed values per
//! dimension, so intersection is a bitwise AND and set difference splits into disjoint cubes.

use crate::model::{err, Dimension, Effect, Policy, Result};
use std::collections::BTreeMap;

pub type Cube = Vec<u64>;

pub struct Space {
    pub dims: Vec<Dimension>,
}

#[derive(Debug, Clone)]
pub struct Region {
    pub cube: Cube,
    pub effect: Effect,
    /// Index of the rule that decides this region, or None for the default deny.
    pub rule: Option<usize>,
}

fn mask(n: usize) -> u64 {
    if n == 64 {
        u64::MAX
    } else {
        (1u64 << n) - 1
    }
}

pub fn is_empty(c: &Cube) -> bool {
    c.contains(&0)
}

pub fn count(c: &Cube) -> u64 {
    c.iter().map(|m| m.count_ones() as u64).product()
}

pub fn intersect(a: &Cube, b: &Cube) -> Option<Cube> {
    let c: Cube = a.iter().zip(b).map(|(x, y)| x & y).collect();
    if is_empty(&c) {
        None
    } else {
        Some(c)
    }
}

/// a minus b, as disjoint cubes.
pub fn subtract(a: &Cube, b: &Cube) -> Vec<Cube> {
    if intersect(a, b).is_none() {
        return vec![a.clone()];
    }
    let mut out = Vec::new();
    let mut rest = a.clone();
    for i in 0..a.len() {
        let outside = rest[i] & !b[i];
        if outside != 0 {
            let mut piece = rest.clone();
            piece[i] = outside;
            out.push(piece);
        }
        rest[i] &= b[i];
    }
    out
}

pub fn subtract_all(cubes: Vec<Cube>, b: &Cube) -> Vec<Cube> {
    cubes.iter().flat_map(|c| subtract(c, b)).collect()
}

/// Merge cubes that differ in a single dimension, so reports stay short.
pub fn simplify(mut cubes: Vec<Cube>) -> Vec<Cube> {
    loop {
        let mut merged = false;
        'scan: for i in 0..cubes.len() {
            for j in (i + 1)..cubes.len() {
                let differing: Vec<usize> = (0..cubes[i].len())
                    .filter(|&k| cubes[i][k] != cubes[j][k])
                    .collect();
                if differing.len() <= 1 {
                    if let Some(&k) = differing.first() {
                        cubes[i][k] |= cubes[j][k];
                    }
                    cubes.swap_remove(j);
                    merged = true;
                    break 'scan;
                }
            }
        }
        if !merged {
            return cubes;
        }
    }
}

impl Space {
    pub fn new(policy: &Policy) -> Space {
        Space {
            dims: policy.dimensions.clone(),
        }
    }

    pub fn full(&self) -> Cube {
        self.dims.iter().map(|d| mask(d.values.len())).collect()
    }

    pub fn size(&self) -> u64 {
        count(&self.full())
    }

    pub fn cube(&self, when: &BTreeMap<String, Vec<String>>) -> Cube {
        let mut c = self.full();
        for (i, d) in self.dims.iter().enumerate() {
            if let Some(values) = when.get(&d.name) {
                c[i] = d
                    .values
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| values.contains(v))
                    .fold(0, |m, (bit, _)| m | (1 << bit));
            }
        }
        c
    }

    /// Only the restricted dimensions, values in domain order.
    pub fn describe(&self, c: &Cube) -> BTreeMap<String, Vec<String>> {
        let full = self.full();
        let mut out = BTreeMap::new();
        for (i, d) in self.dims.iter().enumerate() {
            if c[i] != full[i] {
                let values = (0..d.values.len())
                    .filter(|bit| c[i] & (1 << bit) != 0)
                    .map(|bit| d.values[bit].clone())
                    .collect();
                out.insert(d.name.clone(), values);
            }
        }
        out
    }

    /// A concrete request as a one-point cube.
    pub fn point(&self, request: &BTreeMap<String, String>) -> Result<Cube> {
        for key in request.keys() {
            if !self.dims.iter().any(|d| &d.name == key) {
                return err(format!("unknown dimension '{key}'"));
            }
        }
        let mut c = Vec::with_capacity(self.dims.len());
        for d in &self.dims {
            let Some(v) = request.get(&d.name) else {
                return err(format!("missing dimension '{}'", d.name));
            };
            let Some(bit) = d.values.iter().position(|x| x == v) else {
                return err(format!("unknown value '{v}' for '{}'", d.name));
            };
            c.push(1u64 << bit);
        }
        Ok(c)
    }
}

/// First match wins, anything unmatched is denied. Returns disjoint regions covering the space.
pub fn partition(space: &Space, policy: &Policy) -> Vec<Region> {
    let mut covered: Vec<Cube> = Vec::new();
    let mut regions = Vec::new();
    for (i, rule) in policy.rules.iter().enumerate() {
        let mut pieces = vec![space.cube(&rule.when)];
        for c in &covered {
            pieces = subtract_all(pieces, c);
            if pieces.is_empty() {
                break;
            }
        }
        for p in pieces {
            covered.push(p.clone());
            regions.push(Region {
                cube: p,
                effect: rule.effect,
                rule: Some(i),
            });
        }
    }
    let mut rest = vec![space.full()];
    for c in &covered {
        rest = subtract_all(rest, c);
    }
    regions.extend(rest.into_iter().map(|cube| Region {
        cube,
        effect: Effect::Deny,
        rule: None,
    }));
    regions
}
