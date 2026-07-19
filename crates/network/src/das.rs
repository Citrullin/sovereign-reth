//! IPFS & Data Availability Sampling (DAS) Module.
//!
//! Implements a Celestia-style 2D Reed-Solomon/Parity erasure coding grid
//! and light client Data Availability Sampling via simulated random DHT queries.

use std::collections::HashSet;

use reed_solomon_erasure::galois_8::ReedSolomon;

/// An erasure coded 2D grid containing data and parity chunks stored as a flat buffer.
///
/// The grid is 2k × 2k cells, each cell being `chunk_size` bytes.
/// Stored as a single contiguous allocation for cache efficiency and to avoid
/// the triple indirection of `Vec<Vec<Vec<u8>>>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErasureGrid {
    /// Dimension of the original data grid (k × k).
    pub k: usize,
    /// Size of each individual chunk in bytes.
    pub chunk_size: usize,
    /// Flat buffer: `(2k × 2k × chunk_size)` bytes.
    /// Access cell `(row, col)` via [`ErasureGrid::chunk`] / [`ErasureGrid::chunk_mut`].
    data: Vec<u8>,
}

impl ErasureGrid {
    /// Returns the full grid dimension (2k).
    #[must_use]
    pub fn size(&self) -> usize {
        2 * self.k
    }

    /// Returns an immutable view of the chunk at `(row, col)`.
    #[must_use]
    pub fn chunk(&self, row: usize, col: usize) -> &[u8] {
        let size = self.size();
        let offset = (row * size + col) * self.chunk_size;
        &self.data[offset..offset + self.chunk_size]
    }

    /// Returns a mutable view of the chunk at `(row, col)`.
    pub fn chunk_mut(&mut self, row: usize, col: usize) -> &mut [u8] {
        let size = self.size();
        let offset = (row * size + col) * self.chunk_size;
        &mut self.data[offset..offset + self.chunk_size]
    }

    /// Creates a new `ErasureGrid` by encoding raw input data using 2D Reed-Solomon.
    ///
    /// # Errors
    /// Returns an error if encoding fails or if `k` or `chunk_size` is zero.
    pub fn encode(data: &[u8], k: usize, chunk_size: usize) -> Result<Self, &'static str> {
        if k == 0 || chunk_size == 0 {
            return Err("Invalid grid size or chunk size");
        }

        let size = 2 * k;
        let total_cells = size * size;

        // Allocate a single flat buffer for the entire extended grid.
        let mut flat = vec![0u8; total_cells * chunk_size];

        // Helper closures that operate on the flat buffer directly.
        let cell_offset = |row: usize, col: usize| (row * size + col) * chunk_size;

        // 1. Fill data quadrant (0..k, 0..k) from the input.
        for (i, chunk) in data.chunks(chunk_size).enumerate() {
            if i >= k * k {
                break;
            }
            let (row, col) = (i / k, i % k);
            let offset = cell_offset(row, col);
            flat[offset..offset + chunk.len()].copy_from_slice(chunk);
        }

        let r_s = ReedSolomon::new(k, k).map_err(|_| "Failed to initialize RS encoder")?;

        // 2. Encode rows (0..k): extend data quadrant to 2k columns.
        //    Build temporary slice views into the flat buffer per row.
        for r in 0..k {
            // Collect slices for each column cell in this row.
            // We need `Vec<Vec<u8>>` because `reed_solomon_erasure` takes owned shards.
            let mut shards: Vec<Vec<u8>> = (0..size)
                .map(|c| flat[cell_offset(r, c)..cell_offset(r, c) + chunk_size].to_vec())
                .collect();
            r_s.encode(&mut shards).map_err(|_| "Failed to encode row parity")?;
            for (c, shard) in shards.iter().enumerate().take(size) {
                let offset = cell_offset(r, c);
                flat[offset..offset + chunk_size].copy_from_slice(shard);
            }
        }

        // 3. Encode columns (0..2k): extend top k rows to 2k rows.
        for c in 0..size {
            let mut shards: Vec<Vec<u8>> = (0..size)
                .map(|r| flat[cell_offset(r, c)..cell_offset(r, c) + chunk_size].to_vec())
                .collect();
            r_s.encode(&mut shards).map_err(|_| "Failed to encode column parity")?;
            for (r, shard) in shards.iter().enumerate().take(size) {
                let offset = cell_offset(r, c);
                flat[offset..offset + chunk_size].copy_from_slice(shard);
            }
        }

        Ok(Self { k, chunk_size, data: flat })
    }

    /// Verifies if a specific chunk is mathematically consistent with its row parity.
    #[must_use]
    pub fn verify_chunk(&self, row: usize, col: usize) -> bool {
        let size = self.size();
        if row >= size || col >= size {
            return false;
        }

        let Ok(r_s) = ReedSolomon::new(self.k, self.k) else {
            return false;
        };

        // Build shard references from the flat buffer — no copies needed here.
        let shards: Vec<&[u8]> = (0..size).map(|c| self.chunk(row, c)).collect();
        r_s.verify(&shards).unwrap_or(false)
    }
}

/// DA Sampling Light Node configuration.
pub struct DasLightNode {
    /// Minimum random samples required per block.
    pub required_samples: usize,
}

impl Default for DasLightNode {
    fn default() -> Self {
        Self { required_samples: 16 }
    }
}

impl DasLightNode {
    /// Performs Data Availability Sampling via IPFS DHT queries.
    ///
    /// Simulates 16 random IPFS DHT queries on coordinates from the [`ErasureGrid`].
    ///
    /// # Errors
    /// Returns an error if sampling fails or fewer than 16 successful queries are obtained.
    pub fn perform_das(&self, grid: &ErasureGrid, simulated_drops: &HashSet<(usize, usize)>) -> Result<bool, &'static str> {
        let size = grid.size();
        let total_cells = size * size;
        let samples_needed = self.required_samples.min(total_cells);
        let mut sampled_coords = HashSet::new();

        let mut seed = 42usize;
        let mut successful_samples = 0;
        let mut attempts = 0;

        while sampled_coords.len() < samples_needed {
            attempts += 1;
            let (row, col) = if attempts < 1000 {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
                let r = seed % size;
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
                let c = seed % size;
                (r, c)
            } else {
                let idx = attempts - 1000;
                let r = (idx / size) % size;
                let c = idx % size;
                (r, c)
            };

            if sampled_coords.insert((row, col)) {
                if simulated_drops.contains(&(row, col)) {
                    return Ok(false);
                }

                if !grid.verify_chunk(row, col) {
                    return Err("Sample validation failed due to mathematical inconsistency");
                }

                successful_samples += 1;
            }
        }

        Ok(successful_samples >= samples_needed)
    }

    /// Applies 2D Reed-Solomon/Parity erasure coding to IPLD chunks.
    ///
    /// Returns the flattened bytes of the extended grid, or an empty `Vec` on failure.
    #[must_use]
    pub fn apply_reed_solomon_2d(&self, data: &[u8]) -> Vec<u8> {
        if let Ok(grid) = ErasureGrid::encode(data, 2, 256) {
            grid.data.clone()
        } else {
            vec![]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_erasure_grid_encoding() {
        let original_data = vec![1u8; 1024]; // 4 chunks of size 256
        let grid = ErasureGrid::encode(&original_data, 2, 256).unwrap();

        assert_eq!(grid.k, 2);
        let size = grid.size(); // 2k = 4
        // Flat buffer: 4*4*256 = 4096 bytes
        assert_eq!(grid.data.len(), size * size * 256);

        // Data quadrant (0..2, 0..2) should match original data chunks
        assert_eq!(grid.chunk(0, 0), vec![1u8; 256].as_slice());
        assert_eq!(grid.chunk(1, 1), vec![1u8; 256].as_slice());
    }

    #[test]
    fn test_erasure_grid_chunk_verification() {
        let original_data = vec![2u8; 1024];
        let mut grid = ErasureGrid::encode(&original_data, 2, 256).unwrap();

        // Verify valid chunk
        assert!(grid.verify_chunk(0, 0));
        assert!(grid.verify_chunk(0, 2)); // Parity chunk

        // Corrupt a chunk and assert verification fails
        grid.chunk_mut(0, 0)[0] = 99;
        assert!(!grid.verify_chunk(0, 2));
    }

    #[test]
    fn test_perform_das_success() {
        let original_data = vec![5u8; 1024];
        let grid = ErasureGrid::encode(&original_data, 2, 256).unwrap();
        let light_node = DasLightNode::default();
        let drops = HashSet::new();

        let res = light_node.perform_das(&grid, &drops).unwrap();
        assert!(res);
    }

    #[test]
    fn test_perform_das_failure_on_missing_chunk() {
        let original_data = vec![5u8; 1024];
        let grid = ErasureGrid::encode(&original_data, 2, 256).unwrap();
        let light_node = DasLightNode::default();

        // Drop all chunks to force failure
        let mut drops = HashSet::new();
        let size = grid.size();
        for r in 0..size {
            for c in 0..size {
                drops.insert((r, c));
            }
        }

        let res = light_node.perform_das(&grid, &drops).unwrap();
        assert!(!res);
    }
}
