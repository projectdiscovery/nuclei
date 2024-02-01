package utils

import (
	"database/sql"
)

// SQLResult holds the result of a SQL query.
//
// It contains the count of rows, the columns present, and the actual row data.
type SQLResult struct {
	Count   int           // Count is the number of rows returned.
	Columns []string      // Columns is the slice of column names.
	Rows    []interface{} // Rows is a slice of row data, where each row is a map of column name to value.
}

// UnmarshalSQLRows converts sql.Rows into a more structured SQLResult.
//
// This function takes *sql.Rows as input and attempts to unmarshal the data into
// a SQLResult struct. It handles different SQL data types by using the appropriate
// sql.Null* types during scanning. It returns a pointer to a SQLResult or an error.
//
// The function closes the sql.Rows when finished.
func UnmarshalSQLRows(rows *sql.Rows) (*SQLResult, error) {
	defer rows.Close()
	columnTypes, err := rows.ColumnTypes()
	if err != nil {
		return nil, err
	}
	result := &SQLResult{}
	result.Columns, err = rows.Columns()
	if err != nil {
		return nil, err
	}

	count := len(columnTypes)
	for rows.Next() {
		result.Count++
		scanArgs := make([]interface{}, count)
		for i, v := range columnTypes {
			switch v.DatabaseTypeName() {
			case "VARCHAR", "TEXT", "UUID", "TIMESTAMP":
				scanArgs[i] = new(sql.NullString)
			case "BOOL":
				scanArgs[i] = new(sql.NullBool)
			case "INT4":
				scanArgs[i] = new(sql.NullInt64)
			default:
				scanArgs[i] = new(sql.NullString)
			}
		}
		err := rows.Scan(scanArgs...)
		if err != nil {
			// Return the result accumulated so far along with the error.
			return result, err
		}
		masterData := make(map[string]interface{})
		for i, v := range columnTypes {
			if z, ok := (scanArgs[i]).(*sql.NullBool); ok {
				masterData[v.Name()] = z.Bool
				continue
			}

			if z, ok := (scanArgs[i]).(*sql.NullString); ok {
				masterData[v.Name()] = z.String
				continue
			}

			if z, ok := (scanArgs[i]).(*sql.NullInt64); ok {
				masterData[v.Name()] = z.Int64
				continue
			}

			if z, ok := (scanArgs[i]).(*sql.NullFloat64); ok {
				masterData[v.Name()] = z.Float64
				continue
			}

			if z, ok := (scanArgs[i]).(*sql.NullInt32); ok {
				masterData[v.Name()] = z.Int32
				continue
			}

			masterData[v.Name()] = scanArgs[i]
		}
		result.Rows = append(result.Rows, masterData)
	}
	return result, nil
}
