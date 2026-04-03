from .clickhouse_indexer import ClickHouseIndexer, get_indexer

# Legacy alias for backward compatibility during migration
ElasticIndexer = ClickHouseIndexer

__all__ = ["ClickHouseIndexer", "get_indexer", "ElasticIndexer"]
