drop table if exists teestore;
create table teestore (
    ks_id varchar(40) not null,
    chain varchar(40),
    chain_addr varchar(100),
    cond_type varchar(20),
    d_cond_type varchar(20),
    tee_cond_type varbinary(100),
    tee_cond_value varbinary(100),
    tee_d_cond_type varbinary(100),
    tee_d_cond_value varbinary(100),
    tee_content varbinary(8192),
    INDEX ks_id using hash(ks_id),
    INDEX ks_addr using hash(chain_addr),
    PRIMARY KEY(ks_id, chain, chain_addr)
)
ROW_FORMAT=COMPRESSED
CHARACTER set = utf8mb4;
