#include "hash.h"
#include "common.h"

typedef struct hash_node
{
	void *key;
	void *value;
	struct hash_node *prev;
	struct hash_node *next;
} hash_node_t;


struct hash
{
	unsigned int buckets;
	hashfunc_t hash_func;
	hash_node_t **nodes;
};

hash_node_t **hash_get_buckets(hash_t *hash, void *key);
hash_node_t *hash_get_node_by_key(hash_t *hash, void *key, unsigned int key_size);

hash_t *hash_alloc(unsigned int buckets, hashfunc_t hash_func)
{
	hash_t *hash = (hash_t *)malloc(sizeof(hash_t));
	hash->buckets = buckets;
	hash->hash_func = hash_func;
	hash->nodes = (hash_node_t **)malloc(buckets*sizeof(hash_node_t *));	
	memset(hash->nodes, 0, buckets*sizeof(hash_node_t *));
	return hash;
}

void *hash_lookup_entry(hash_t *hash, void *key, unsigned int key_size)
{
	hash_node_t *node = hash_get_node_by_key(hash, key, key_size);
	if (node == NULL)
	{
		return NULL;
	}	
	return node->value;
}

void hash_add_entry(hash_t *hash, void *key, unsigned int key_size, 
					void *value, unsigned int value_size)
{
	// 相同key的hash_node已存在
	if (hash_lookup_entry(hash, key, key_size))
	{
		fprintf(stderr, "duplicate hash key\n");
		return;
	}

	hash_node_t *node = (hash_node_t *)malloc(sizeof(hash_node_t));
	//memset(node, 0, sizeof(hash_node_t));
	node->prev = NULL;
	node->next = NULL;

	node->key = malloc(key_size);
	memcpy(node->key, key, key_size);

	node->value = malloc(value_size);
	memcpy(node->value, value, value_size);

	hash_node_t **bucket = hash_get_buckets(hash, key);
	if (*bucket == NULL)
	{
		*bucket = node;
	}
	else
	{
		// 将新节点插入到链表头部
		node->next = (*bucket);
		node->next->prev = node;
		(*bucket) = node;
	}
}

void hash_free_entry(hash_t *hash, void *key, unsigned int key_size)
{
	hash_node_t *node = hash_get_node_by_key(hash, key, key_size);
	if (node)
	{
		free(node->key);
		free(node->value);

		if (node->prev)
		{
			node->prev->next = node->next;
		}
		else
		{
			hash_node_t **bucket = hash_get_buckets(hash, key);
			(*bucket) = node->next;
		}
		
		if (node->next)
		{
			node->next->prev = node->prev;
		}
		free(node);
	}
}

// 注意这里返回的是指针数组 中元素的地址
hash_node_t **hash_get_buckets(hash_t *hash, void *key)
{
	int index = hash->hash_func(hash->buckets, key);
	if (index >= hash->buckets)
	{
		return NULL;
	}
	return &hash->nodes[index];
}

hash_node_t *hash_get_node_by_key(hash_t *hash, void *key, unsigned int key_size)
{
	hash_node_t **bucket = hash_get_buckets(hash, key);
	hash_node_t *node = *bucket;
	if (node == NULL)
	{
		return NULL;
	}

	//while (node && memcpy(node->key, key, key_size) != 0)
	while (node && memcmp(node->key, key, key_size) != 0)
	{
		node = node->next;
	}
	return node;
}

// 仅适用于key为int类型
void hash_status_print(hash_t *hash)
{
	for (int i=0; i<hash->buckets; ++i)
	{
		printf("[%d]:", i);
		hash_node_t *node = hash->nodes[i];
		while (node)
		{
			//printf("(key=%d, value=%d) ",*(int *)node->key, *(int *)node->value);
			printf("(key=%d) ",*(int *)node->key);
			node = node->next;
		}
		printf("\n");
	}	
}

