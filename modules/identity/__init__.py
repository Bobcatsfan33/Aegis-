class _StubClickHouse:
    @staticmethod
    def is_available():
        return False
    @staticmethod
    def query(sql):
        return []
    @staticmethod
    def execute(sql, params=None):
        pass

clickhouse_client = _StubClickHouse()
