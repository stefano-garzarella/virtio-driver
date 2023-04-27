// SPDX-License-Identifier: (MIT OR Apache-2.0)

use std::collections::BTreeMap;
use std::io::{self, ErrorKind};
use std::ops::RangeInclusive;

/// Wraps a `u64` representing an IOVA.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Iova(pub u64);

#[derive(Clone, Copy, Debug)]
struct IovaMapping {
    base_address: usize,
    base_iova: Iova,
    size: usize,
}

#[derive(Debug)]
pub struct IovaSpace {
    pools: Box<[RangeInclusive<Iova>]>,
    mappings_by_iova: BTreeMap<Iova, IovaMapping>,
    mappings_by_address: BTreeMap<usize, IovaMapping>,
}

impl IovaSpace {
    // Ranges must be in increasing IOVA order, and must not overlap.
    pub fn new(available_ranges: impl IntoIterator<Item = RangeInclusive<Iova>>) -> IovaSpace {
        let pools: Box<[RangeInclusive<Iova>]> = available_ranges.into_iter().collect();
        assert!(pools.windows(2).all(|r| r[0].end() < r[1].start()));

        IovaSpace {
            pools,
            mappings_by_address: BTreeMap::new(),
            mappings_by_iova: BTreeMap::new(),
        }
    }

    pub fn allocate(&mut self, address: usize, size: usize) -> io::Result<Iova> {
        if let Some(mapping) = self.get_mapping_intersecting(address, size) {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("Address {:#x} is already mapped", mapping.base_address),
            ));
        }

        let mapping = self.find_free_iova_range(address, size).ok_or_else(|| {
            io::Error::new(
                ErrorKind::Other,
                format!(
                    "IOVA space is too small or fragmented to allocate a {}-byte range",
                    size
                ),
            )
        })?;

        self.mappings_by_address
            .insert(mapping.base_address, mapping);
        self.mappings_by_iova.insert(mapping.base_iova, mapping);

        Ok(mapping.base_iova)
    }

    fn find_free_iova_range(&self, address: usize, size: usize) -> Option<IovaMapping> {
        let mut mappings = self.mappings_by_iova.values().peekable();

        for pool in self.pools.iter() {
            let mut tentative = IovaMapping {
                base_address: address,
                base_iova: *pool.start(),
                size,
            };

            while let Some(m) = mappings.peek() {
                if m.base_iova.0 > pool.end().0 {
                    break; // no more mappings in the current pool
                } else if m.base_iova.0 > tentative.base_iova.0 + (size as u64 - 1) {
                    return Some(tentative);
                } else {
                    tentative.base_iova.0 = m.base_iova.0 + m.size as u64;
                    mappings.next();
                }
            }

            if tentative.base_iova.0 + (size as u64 - 1) <= pool.end().0 {
                return Some(tentative);
            }
        }

        None
    }

    /// Frees all regions that intersect the given address range.
    pub fn free(&mut self, address: usize, size: usize) {
        while let Some(&mapping) = self.get_mapping_intersecting(address, size) {
            self.mappings_by_address.remove(&mapping.base_address);
            self.mappings_by_iova.remove(&mapping.base_iova);
        }
    }

    pub fn translate(&self, address: usize, size: usize) -> Option<Iova> {
        let mapping = self.get_mapping_containing(address, size)?;
        let iova = Iova(mapping.base_iova.0 + (address - mapping.base_address) as u64);
        Some(iova)
    }

    /// Returns the last mapping (base address-wise) whose address range intersects the given range.
    fn get_mapping_intersecting(&self, address: usize, size: usize) -> Option<&IovaMapping> {
        self.mappings_by_address
            .range(..address + size)
            .next_back()
            .map(|(_, m)| m)
            .filter(|m| address < m.base_address + m.size)
    }

    /// Returns the mapping whose address range fully contains the given range.
    fn get_mapping_containing(&self, address: usize, size: usize) -> Option<&IovaMapping> {
        self.mappings_by_address
            .range(..=address)
            .next_back()
            .map(|(_, m)| m)
            .filter(|m| address + size <= m.base_address + m.size)
    }
}
