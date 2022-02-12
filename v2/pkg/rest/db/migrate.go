package db

import "context"

const migrationData = `CREATE TABLE IF NOT EXISTS "public".templates ( 
	id                   bigserial NOT NULL,
	name                 varchar(100) NOT NULL,
	folder               varchar NOT NULL,
	"path"               varchar  NOT NULL,
	contents             text  NOT NULL,
	createdat            timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updatedat            date  NOT NULL DEFAULT CURRENT_DATE,
    hash                 varchar  NOT NULL,
	CONSTRAINT pk_templates_id PRIMARY KEY ( id ),
	CONSTRAINT idx_unique_paths UNIQUE ( "path" ) 
);

CREATE TABLE IF NOT EXISTS "public".targets ( 
	id                   bigserial NOT NULL ,
	name                 varchar(100) NOT NULL,
    internalid           varchar NOT NULL,
    filename             varchar NOT NULL,
    total                bigint NOT NULL,
	createdat            timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP  ,
	updatedat            timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP  ,
	CONSTRAINT pk_targets_id PRIMARY KEY ( id )
 );


CREATE TABLE IF NOT EXISTS "public".settings ( 
	settingdata          varchar NOT NULL,
	datatype             varchar NOT NULL,
	name                 varchar(100) NOT NULL,
	CONSTRAINT unq_settings UNIQUE ( name ) 
 );


CREATE TABLE IF NOT EXISTS "public".scans ( 
	name                 varchar(100) NOT NULL,
	status               varchar(30) NOT NULL,
	scantime             bigint NOT NULL,
	hosts                bigint NOT NULL,
	scansource           varchar NOT NULL,
	templates            varchar[] NOT NULL,
	targets              varchar[] NOT NULL,
	config				 varchar,
	runnow 				 boolean,
	reporting 			 varchar,
	scheduleoccurence 	 varchar,
	scheduletime 		 varchar,
	id                   bigserial NOT NULL,
	CONSTRAINT pk_scans_id PRIMARY KEY ( id )
);

CREATE TABLE IF NOT EXISTS "public".issues ( 
	matchedat            varchar NOT NULL,
	title                varchar NOT NULL,
	severity             varchar NOT NULL,
	createdat            timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP  ,
	updatedat            timestamptz  NOT NULL DEFAULT CURRENT_TIMESTAMP  ,
	scansource           varchar NOT NULL,
	issuestate           varchar NOT NULL,
	description          varchar NOT NULL,
	author               varchar NOT NULL,
	cvss                 float8,
	cwe                  integer[],
	labels               varchar[],
	issuedata            text NOT NULL,
	issuetemplate        text NOT NULL,
	templatename         varchar NOT NULL,
	remediation          text,
	hash				 varchar NOT NULL,
	id                   bigserial NOT NULL,
	scanid               bigint NOT NULL,
	CONSTRAINT pk_issues_id PRIMARY KEY ( id ),
	CONSTRAINT unq_hash UNIQUE ( hash ) 
);`

// Migrate runs the db migrations creating tables etc
func (d *Database) Migrate() error {
	_, err := d.pool.Exec(context.Background(), migrationData)
	return err
}
