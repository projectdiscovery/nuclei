CREATE TABLE public.templates ( 
	id                   bigserial  NOT NULL ,
	name                 varchar(100)   ,
	folder               varchar   ,
	"path"               varchar  NOT NULL ,
	contents             text  NOT NULL ,
	createdat            timestamptz DEFAULT CURRENT_TIMESTAMP  ,
	updatedat            date DEFAULT CURRENT_DATE  ,
	CONSTRAINT pk_templates_id PRIMARY KEY ( id ),
	CONSTRAINT idx_unique_paths UNIQUE ( "path" ) 
);

CREATE TABLE public.targets ( 
	id                   bigserial  NOT NULL ,
	name                 varchar(100)   ,
	filepath             varchar  NOT NULL ,
	total                bigint   ,
	createdat            timestamptz DEFAULT CURRENT_TIMESTAMP  ,
	updatedat            timestamptz DEFAULT CURRENT_TIMESTAMP  ,
	CONSTRAINT pk_targets_id PRIMARY KEY ( id )
);

CREATE  TABLE "public".settings ( 
	alerting             json   ,
	config               json   
);

CREATE  TABLE "public".scans ( 
	name                 varchar(100)   ,
	status               varchar(30)   ,
	scantime             time   ,
	hosts                bigint   ,
	scansource           varchar   ,
	progress             float8   ,
	templates            varchar[]   ,
	targets              varchar[]   ,
	debug                boolean   ,
	id                   bigserial NOT NULL ,
	CONSTRAINT pk_scans_id PRIMARY KEY ( id )
);

CREATE  TABLE "public".issues ( 
	matchedat            varchar   ,
	title                varchar   ,
	severity             varchar   ,
	createdat            timestamptz DEFAULT CURRENT_TIMESTAMP  ,
	updatedat            timestamptz DEFAULT CURRENT_TIMESTAMP  ,
	scansource           varchar   ,
	issuestate           varchar   ,
	description          varchar   ,
	author               varchar   ,
	cvss                 integer[]   ,
	cwe                  integer[]   ,
	labels               varchar[]   ,
	issuedata            text   ,
	issuetemplate        text   ,
	remediation          text   ,
	debug                text   ,
	id                   bigserial NOT NULL ,
	scanid               bigint   ,
	CONSTRAINT pk_issues_id PRIMARY KEY ( id )
);


-- name: GetTemplates :many
SELECT id, name, folder, "path", contents, createdat, updatedat
FROM
	"public".templates;

-- name: DeleteTemplate :exec
DELETE FROM public.templates WHERE path=$1;

-- name: GetTemplateContents :one
SELECT contents FROM public.templates WHERE path=$1;

-- name: AddTemplate :exec
INSERT INTO public.templates
( name, folder, "path", contents, createdat, updatedat) VALUES ($1, $2, $3 , $4, NOW(), NOW() );

-- name: UpdateTemplate :exec
UPDATE public.templates SET contents=$1, updatedat=$2 WHERE path=$3;

-- name: DeleteTarget :exec
DELETE FROM public.targets WHERE ID=$1;

-- name: AddTarget :exec
INSERT INTO public.targets
	( name, filepath, total, createdat, updatedat) VALUES ($1, $2, $3, NOW(), NOW());

-- name: GetTarget :one
SELECT filepath, total, createdat, updatedat
FROM
	public.targets WHERE ID=$1;

-- name: GetTargets :many
SELECT id, name, filepath, total, createdat, updatedat
FROM
	public.targets;

-- name: AddScan :exec
INSERT INTO "public".scans
	(name, status, hosts, scansource, progress, templates, targets, debug) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: DeleteScan :exec
DELETE FROM "public".scans WHERE id=$1;

-- name: GetScan :one
SELECT name, status, scantime, hosts, scansource, progress, templates, targets, debug, id
FROM
	"public".scans WHERE id=$1;

-- name: GetScans :many
SELECT id, name, status, scantime, hosts, scansource, progress
FROM
	"public".scans;

-- name: AddIssue :exec
INSERT INTO "public".issues
	(matchedat, title, severity, createdat, updatedat, scansource, issuestate, description, author, cvss, cwe, labels, issuedata, issuetemplate, remediation, debug) 
VALUES 
    ($1, $2, $3, NOW(), NOW(), $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14 );

-- name: DeleteIssue :exec
DELETE FROM "public".issues WHERE id=$1;

-- name: GetIssue :one
SELECT matchedat, title, severity, createdat, updatedat, scansource, issuestate, description, author, cvss, cwe, labels, 
	issuedata, issuetemplate, remediation, debug, id, scanid
FROM
	"public".issues WHERE id=$1;

-- name: GetIssues :many
SELECT id, scanid, matchedat, title, severity, createdat, updatedat, scansource
FROM
	"public".issues;

-- name: UpdateIssue :exec
UPDATE "public".issues SET issuestate='closed' WHERE id=$1 ;