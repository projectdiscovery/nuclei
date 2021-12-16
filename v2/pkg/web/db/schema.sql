CREATE TABLE "public".templates ( 
	id                   bigserial  NOT NULL,
	name                 varchar(100),
	folder               varchar,
	"path"               varchar  NOT NULL,
	contents             text  NOT NULL,
	createdat            timestamptz DEFAULT CURRENT_TIMESTAMP,
	updatedat            date DEFAULT CURRENT_DATE,
    hash                 varchar   ,
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
	settingdata          varchar   ,
	datatype             varchar   ,
	name                 varchar(100)   ,
	CONSTRAINT unq_settings UNIQUE ( name ) 
 );


CREATE  TABLE "public".scans ( 
	name                 varchar(100),
	status               varchar(30),
	scantime             bigint,
	hosts                bigint,
	scansource           varchar,
	templates            varchar[],
	targets              varchar[],
	config				 varchar,
	runnow 				 boolean,
	reporting 			 varchar,
	scheduleoccurence 	 varchar,
	scheduletime 		 varchar,
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
	templatename         varchar,
	remediation          text,
	debug                text,
	id                   bigserial NOT NULL,
	scanid               bigint,
	CONSTRAINT pk_issues_id PRIMARY KEY ( id )
);

-- name: GetTemplates :many
SELECT id, name, folder, "path", createdat, updatedat, hash
FROM
	"public".templates;

-- name: GetTemplatesByFolder :many
SELECT id, name, "path", createdat, updatedat, hash
FROM
	"public".templates WHERE folder=$1;

-- name: GetTemplatesByFolderOne :one
SELECT id, name, "path", createdat, updatedat, hash
FROM
	"public".templates WHERE folder=$1 LIMIT 1;

-- name: GetTemplatesBySearchKey :many
SELECT id, name, folder, "path", createdat, updatedat, hash
FROM
	"public".templates WHERE path LIKE '%'||$1||'%';

-- name: DeleteTemplate :exec
DELETE FROM public.templates WHERE path=$1;

-- name: GetTemplateContents :one
SELECT contents FROM public.templates WHERE path=$1 LIMIT 1;

-- name: GetTemplatesForScan :many
SELECT path, contents FROM public.templates WHERE folder=$1 OR path=$1 OR path LIKE $1||'%';

-- name: AddTemplate :exec
INSERT INTO public.templates
( name, folder, "path", contents, createdat, updatedat, hash) VALUES ($1, $2, $3 , $4, NOW(), NOW(), $5);

-- name: UpdateTemplate :exec
UPDATE public.templates SET contents=$1, updatedat=$2, hash=$4 WHERE path=$3;

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
	"public".targets WHERE name LIKE '%'||$1||'%' OR filename LIKE '%'||$1||'%';

-- name: UpdateTargetMetadata :exec
UPDATE targets SET total=total+$1 AND updatedAt=NOW() WHERE id=$2;

-- name: AddScan :one
INSERT INTO "public".scans
	( name, status, scantime, hosts, scansource, templates, targets, config, runnow, reporting, scheduleoccurence, scheduletime) VALUES ( $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12 ) RETURNING id;

-- name: DeleteScan :exec
DELETE FROM "public".scans WHERE id=$1;

-- name: GetScan :one
SELECT name, status, scantime, hosts, scansource, templates, targets, config, runnow, reporting, scheduleoccurence, 
	scheduletime, id
FROM
	"public".scans WHERE id=$1 LIMIT 1;

-- name: GetScans :many
SELECT name, status, scantime, hosts, scansource, templates, targets, config, runnow, reporting, scheduleoccurence, 
	scheduletime, id
FROM
	"public".scans;

-- name: GetScansBySearchKey :many
SELECT name, status, scantime, hosts, scansource, templates, targets, config, runnow, reporting, scheduleoccurence, 
	scheduletime, id
FROM
	"public".scans WHERE name LIKE '%'||$1||'%';

-- name: AddIssue :exec
INSERT INTO "public".issues
	(matchedat, title, severity, createdat, updatedat, scansource, issuestate, description, author, cvss, cwe, labels, issuedata, issuetemplate, templatename, remediation, debug, scanid) 
VALUES 
    ($1, $2, $3, NOW(), NOW(), $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16);

-- name: DeleteIssue :exec
DELETE FROM "public".issues WHERE id=$1;


-- name: DeleteIssueByScanID :exec
DELETE FROM "public".issues WHERE scanid=$1;

-- name: GetIssue :one
SELECT matchedat, title, severity, createdat, updatedat, scansource, issuestate, description, author, cvss, cwe, labels, 
	issuedata, issuetemplate, templatename, remediation, debug, id, scanid
FROM
	"public".issues WHERE id=$1 LIMIT 1;

-- name: GetIssues :many
SELECT id, scanid, matchedat, title, severity, createdat, updatedat, scansource
FROM
	"public".issues;

-- name: GetIssuesMatches :many
SELECT id, matchedat, templatename, severity, author
FROM
	"public".issues WHERE scanid=$1;

-- name: UpdateIssue :exec
UPDATE "public".issues SET issuestate='closed' WHERE id=$1 ;

-- name: SetSettings :exec
INSERT INTO "public".settings
	( settingdata, datatype, name) VALUES ( $1, $2, $3) ON CONFLICT (name) DO UPDATE SET settingdata=$1;

-- name: GetSettings :many
SELECT settingdata, datatype, name
FROM
	"public".settings;

-- name: GetSettingByName :one
SELECT settingdata, datatype
FROM
	"public".settings WHERE name=$1 LIMIT 1;


-- name: UpdateSettings :exec
UPDATE "public".settings SET settingdata=$1 WHERE name=$2;
