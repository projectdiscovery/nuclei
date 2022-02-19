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

CREATE TABLE IF NOT EXISTS "public".versions ( 
	id                   int NOT NULL,
	templates            varchar NOT NULL,
	CONSTRAINT idx_unique_id UNIQUE ( "id" ) 
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
	template			 varchar NOT NULL,
	templateurl          varchar,
	templateid           varchar,
	templatepath         varchar,
	templatename         varchar NOT NULL,
	author      		 varchar,
	labels               varchar[],
	description          varchar NOT NULL,
	reference            varchar[],
	severity             varchar NOT NULL,
	templatemetadata     varchar,
	cvss                 float8,
	cwe                  integer[],
	cveid                varchar,
	cvssmetrics          varchar,
	remediation          varchar,
	matchername			 varchar,
	extractorname        varchar,
    resulttype           varchar NOT NULL,
	host				 varchar NOT NULL,
	path				 varchar,
	matchedat            varchar NOT NULL,
	extractedresults     varchar[],
	request              varchar,
	response             varchar,
	metadata             varchar,
	ip                   varchar,
	interaction          varchar,
	curlcommand          varchar,
	matcherstatus        boolean,
	title                varchar NOT NULL,
	createdat            timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP  ,
	updatedat            timestamptz  NOT NULL DEFAULT CURRENT_TIMESTAMP  ,
	scansource           varchar NOT NULL,
	issuestate           varchar NOT NULL,
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
