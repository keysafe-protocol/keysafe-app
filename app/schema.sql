drop table if exists user;
create table user (
    kid varchar(256) not null,
    uname varchar(256) default '' not null,
    email varchar(256) default '' not null,
    PRIMARY KEY(kid)
);

drop table if exists oauth;
create table oauth (
    kid varchar(256) not null,
    org varchar(256) default '' not null,
    oprofile varchar(8192) default '' not null,
    PRIMARY KEY(kid, org)
);