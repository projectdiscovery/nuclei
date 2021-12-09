CREATE TABLE public.templates ( 
	id                   bigserial  NOT NULL,
	name                 varchar(100),
	folder               varchar,
	"path"               varchar  NOT NULL,
	contents             text  NOT NULL,
	createdat            timestamptz DEFAULT CURRENT_TIMESTAMP,
	updatedat            date DEFAULT CURRENT_DATE,
	CONSTRAINT pk_templates_id PRIMARY KEY ( id ),
	CONSTRAINT idx_unique_paths UNIQUE ( "path" ) 
);

CREATE  TABLE "public".targets ( 
	id                   bigserial NOT NULL ,
	name                 varchar(100)   ,
    internalid           varchar,
    filename             varchar,
    total                bigint,
	createdat            timestamptz DEFAULT CURRENT_TIMESTAMP  ,
	updatedat            timestamptz DEFAULT CURRENT_TIMESTAMP  ,
	CONSTRAINT pk_targets_id PRIMARY KEY ( id )
 );


CREATE  TABLE "public".settings ( 
	alerting             json,
	config               json
);

CREATE  TABLE "public".scans ( 
	name                 varchar(100),
	status               varchar(30),
	scantime             time,
	hosts                bigint,
	scansource           varchar,
	progress             float8,
	templates            varchar[],
	targets              varchar[],
	debug                boolean,
	id                   bigserial NOT NULL,
	CONSTRAINT pk_scans_id PRIMARY KEY ( id )
);

CREATE  TABLE "public".issues ( 
	matchedat            varchar,
	title                varchar,
	severity             varchar,
	createdat            timestamptz DEFAULT CURRENT_TIMESTAMP  ,
	updatedat            timestamptz DEFAULT CURRENT_TIMESTAMP  ,
	scansource           varchar,
	issuestate           varchar,
	description          varchar,
	author               varchar,
	cvss                 float8,
	cwe                  integer[],
	labels               varchar[],
	issuedata            text,
	issuetemplate        text,
	remediation          text,
	debug                text,
	id                   bigserial NOT NULL,
	scanid               bigint,
	CONSTRAINT pk_issues_id PRIMARY KEY ( id )
);


-- name: GetTemplates :many
SELECT id, name, folder, "path", createdat, updatedat
FROM
	"public".templates;

-- name: GetTemplatesByFolder :many
SELECT id, name, "path", createdat, updatedat
FROM
	"public".templates WHERE folder=$1;

-- name: GetTemplatesBySearchKey :many
SELECT id, name, folder, "path", createdat, updatedat
FROM
	"public".templates WHERE path LIKE $1;

-- name: DeleteTemplate :exec
DELETE FROM public.templates WHERE path=$1;

-- name: GetTemplateContents :one
SELECT contents FROM public.templates WHERE path=$1 LIMIT 1;

-- name: AddTemplate :exec
INSERT INTO public.templates
( name, folder, "path", contents, createdat, updatedat) VALUES ($1, $2, $3 , $4, NOW(), NOW() );

-- name: UpdateTemplate :exec
UPDATE public.templates SET contents=$1, updatedat=$2 WHERE path=$3;

-- name: DeleteTarget :exec
DELETE FROM public.targets WHERE ID=$1;

-- name: AddTarget :exec
INSERT INTO public.targets
	( name, createdat, updatedat, internalid, filename, total) VALUES ($1, NOW(), NOW(), $2, $3, $4);

-- name: GetTarget :one
SELECT name, internalid, filename, total, createdat, updatedat
FROM
	public.targets WHERE ID=$1 LIMIT 1;

-- name: GetTargetByName :one
SELECT id, internalid, filename, total, createdat, updatedat
FROM
	public.targets WHERE name=$1 LIMIT 1;

-- name: GetTargets :many
SELECT id, name, createdat, updatedat, internalid, filename, total
FROM
	public.targets;

-- name: GetTargetsForSearch :many
SELECT id, name, createdat, updatedat, internalid, filename, total
FROM
	"public".targets WHERE name LIKE $1 OR filename LIKE $1;

-- name: UpdateTargetMetadata :exec
UPDATE targets SET total=total+$1 AND updatedAt=NOW() WHERE id=$2;

-- name: AddScan :exec
INSERT INTO "public".scans
	(name, status, hosts, scansource, progress, templates, targets, debug) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: DeleteScan :exec
DELETE FROM "public".scans WHERE id=$1;

-- name: GetScan :one
SELECT name, status, scantime, hosts, scansource, progress, templates, targets, debug, id
FROM
	"public".scans WHERE id=$1 LIMIT 1;

-- name: GetScans :many
SELECT id, name, status, scantime, hosts, scansource, progress
FROM
	"public".scans;

-- name: AddIssue :exec
INSERT INTO "public".issues
	(matchedat, title, severity, createdat, updatedat, scansource, issuestate, description, author, cvss, cwe, labels, issuedata, issuetemplate, remediation, debug, scanid) 
VALUES 
    ($1, $2, $3, NOW(), NOW(), $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15);

-- name: DeleteIssue :exec
DELETE FROM "public".issues WHERE id=$1;

-- name: GetIssue :one
SELECT matchedat, title, severity, createdat, updatedat, scansource, issuestate, description, author, cvss, cwe, labels, 
	issuedata, issuetemplate, remediation, debug, id, scanid
FROM
	"public".issues WHERE id=$1 LIMIT 1;

-- name: GetIssues :many
SELECT id, scanid, matchedat, title, severity, createdat, updatedat, scansource
FROM
	"public".issues;

-- name: UpdateIssue :exec
UPDATE "public".issues SET issuestate='closed' WHERE id=$1 ;