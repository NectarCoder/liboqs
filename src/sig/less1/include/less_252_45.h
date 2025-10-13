#define N (252)
#define K (126)

#define SEED_LENGTH_BYTES (16)
#define SIGN_PIVOT_REUSE_LIMIT (25) // Ensures probability of non-CT operation is < 2^-64
#define NUM_KEYPAIRS (8)
#define T (45)
#define W (34)
#define TREE_OFFSETS {0, 0, 0, 0, 2, 2, 26}
#define TREE_NODES_PER_LEVEL {1, 2, 4, 8, 14, 28, 32}
#define TREE_LEAVES_PER_LEVEL {0, 0, 0, 1, 0, 12, 32}
#define TREE_SUBROOTS 3
#define TREE_LEAVES_START_INDICES {57, 45, 14}
#define TREE_CONSECUTIVE_LEAVES {32, 12, 1}
#define MAX_PUBLISHED_SEEDS 11
