CREATE TABLE testdb.test_table (
    id UInt64,
    name String,
    created_at DateTime
) ENGINE = MergeTree()
PRIMARY KEY (id); 
