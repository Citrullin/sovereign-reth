//! IPFS & Data Availability Sampling (DAS) Module.
//!
//! Implements a Celestia-style 2D Reed-Solomon/Parity erasure coding grid
//! and light client Data Availability Sampling via simulated random DHT queries.

use std::collections::HashSet;

use reed_solomon_erasure::galois_8::ReedSolomon;

/// An erasure coded 2D grid containing data and parity chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErasureGrid {
    /// Dimension of the original data grid (k x k).
    pub k: usize,
    /// The full extended grid of chunks (2k x 2k).
    pub chunks: Vec<Vec<Vec<u8>>>,
}

impl ErasureGrid {
    /// Creates a new ErasureGrid by encoding raw input data using 2D Reed-Solomon.
    ///
    /// # Errors
    /// Returns an error if encoding fails.
    pub fn encode(data: &[u8], k: usize, chunk_size: usize) -> Result<Self, &'static str> {
        if k == 0 || chunk_size == 0 {
            return Err("Invalid grid size or chunk size");
        }

        let total_data_chunks = k * k;
        let mut data_chunks = vec![vec![0u8; chunk_size]; total_data_chunks];

        // Fill data chunks
        for (i, chunk) in data.chunks(chunk_size).enumerate() {
            if i >= total_data_chunks {
                break;
            }
            data_chunks[i][..chunk.len()].copy_from_slice(chunk);
        }

        // Initialize 2k x 2k extended grid
        let size = 2 * k;
        let mut chunks = vec![vec![vec![0u8; chunk_size]; size]; size];

        // 1. Fill data quadrant (0..k, 0..k)
        for r in 0..k {
            for c in 0..k {
                chunks[r][c] = data_chunks[r * k + c].clone();
            }
        }

        // Setup Reed-Solomon encoder for (data_shards = k, parity_shards = k)
        let r_s = ReedSolomon::new(k, k).map_err(|_| "Failed to initialize RS encoder")?;

        // 2. Encode rows (0..k): Extend data quadrant to 2k columns
        for r in 0..k {
            let mut shards: Vec<Vec<u8>> = (0..size).map(|c| chunks[r][c].clone()).collect();
            r_s.encode(&mut shards).map_err(|_| "Failed to encode row parity")?;
            for c in 0..size {
                chunks[r][c] = shards[c].clone();
            }
        }

        // 3. Encode columns (0..2k): Extend top k rows to 2k rows
        for c in 0..size {
            let mut shards: Vec<Vec<u8>> = (0..size).map(|r| chunks[r][c].clone()).collect();
            r_s.encode(&mut shards).map_err(|_| "Failed to encode column parity")?;
            for r in 0..size {
                chunks[r][c] = shards[r].clone();
            }
        }

        Ok(Self { k, chunks })
    }

    /// Verifies if a specific chunk is mathematically consistent with its row parity.
    pub fn verify_chunk(&self, row: usize, col: usize) -> bool {
        let size = 2 * self.k;
        if row >= size || col >= size {
            return false;
        }

        let r_s = match ReedSolomon::new(self.k, self.k) {
            Ok(r) => r,
            Err(_) => return false,
        };

        // Get the entire row shards to verify
        let shards: Vec<Vec<u8>> = (0..size).map(|c| self.chunks[row][c].clone()).collect();
        
        // verify takes a slice of references to shards
        let shard_refs: Vec<&[u8]> = shards.iter().map(|s| s.as_slice()).collect();
        r_s.verify(&shard_refs).unwrap_or(false)
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
    /// Simulates 16 random IPFS DHT queries on coordinates from the ErasureGrid.
    ///
    /// # Errors
    /// Returns an error if sampling fails or less than 16 successful queries are obtained.
    pub fn perform_das(&self, grid: &ErasureGrid, simulated_drops: &HashSet<(usize, usize)>) -> Result<bool, &'static str> {
        let size = 2 * grid.k;
        let total_cells = size * size;
        let samples_needed = self.required_samples.min(total_cells);
        let mut sampled_coords = HashSet::new();

        let mut seed = 42usize;
        let mut successful_samples = 0;
        let mut attempts = 0;

        while sampled_coords.len() < samples_needed {
            attempts += 1;
            let (row, col) = if attempts < 1000 {
                seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                let r = seed % size;
                seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                let c = seed % size;
                (r, c)
            } else {
                let idx = attempts - 1000;
                let r = (idx / size) % size;
                let c = idx % size;
                (r, c)
            };

            if sampled_coords.insert((row, col)) {
                // Query simulated DHT
                if simulated_drops.contains(&(row, col)) {
                    return Ok(false); // Immediate failure if an expected sample is unavailable
                }
                
                // Verify mathematical alignment of the chunk
                if !grid.verify_chunk(row, col) {
                    return Err("Sample validation failed due to mathematical inconsistency");
                }

                successful_samples += 1;
            }
        }

        Ok(successful_samples >= samples_needed)
    }

    /// Applies 2D Reed-Solomon/Parity erasure coding to IPLD chunks.
    pub fn apply_reed_solomon_2d(&self, data: &[u8]) -> Vec<u8> {
        // Encodes the data into a 2x2 grid by default, returning flattened bytes of the extended grid.
        if let Ok(grid) = ErasureGrid::encode(data, 2, 256) {
            let mut flat = Vec::new();
            for r in 0..4 {
                for c in 0..4 {
                    flat.extend_from_slice(&grid.chunks[r][c]);
                }
            }
            flat
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
        // Extended grid size should be 2k x 2k = 4x4
        assert_eq!(grid.chunks.len(), 4);
        assert_eq!(grid.chunks[0].len(), 4);
        
        // Data quadrant (0..2, 0..2) should match original data chunks
        assert_eq!(grid.chunks[0][0], vec![1u8; 256]);
        assert_eq!(grid.chunks[1][1], vec![1u8; 256]);
    }

    #[test]
    fn test_erasure_grid_chunk_verification() {
        let original_data = vec![2u8; 1024];
        let mut grid = ErasureGrid::encode(&original_data, 2, 256).unwrap();

        // Verify valid chunk
        assert!(grid.verify_chunk(0, 0));
        assert!(grid.verify_chunk(0, 2)); // Parity chunk

        // Corrupt a chunk and assert verification fails
        grid.chunks[0][0][0] = 99;
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

        // Simulate drop of a specific chunk that will be sampled
        // With seed=42 and required_samples=16, let's see which chunk is generated:
        // LCG outputs will hit various coordinates. Let's add multiple drops to ensure failure
        let mut drops = HashSet::new();
        for r in 0..4 {
            for c in 0..4 {
                drops.insert((r, c));
            }
        }

        let res = light_node.perform_das(&grid, &drops).unwrap();
        assert!(!res);
    }
}

