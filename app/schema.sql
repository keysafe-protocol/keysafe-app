drop table if exists user;
create table user (
    kid varchar(80) not null,
    uname varchar(40) default '' not null,
    email varchar(100) default '' not null,
    PRIMARY KEY(kid)
);

drop table if exists oauth;
create table oauth (
    kid varchar(80) not null,
    org varchar(100) default '' not null,
    oprofile varchar(8192) default '' not null,
    PRIMARY KEY(kid, org)
);

™