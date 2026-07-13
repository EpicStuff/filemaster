// Ported verbatim from service/netquery/orm/query_runner.go — no changes.
package orm

import (
	"context"
	"fmt"
	"reflect"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type (
	// QueryOption can be specified at RunQuery to alter the behavior
	// of the executed query.
	QueryOption func(opts *queryOpts)

	queryOpts struct {
		Transient    bool
		Args         []interface{}
		NamedArgs    map[string]interface{}
		Result       interface{}
		DecodeConfig DecodeConfig
		Schema       TableSchema
	}
)

// WithTransient marks the query as transient.
func WithTransient() QueryOption {
	return func(opts *queryOpts) {
		opts.Transient = true
	}
}

// WithArgs adds a list of arguments for the query.
func WithArgs(args ...interface{}) QueryOption {
	return func(opts *queryOpts) {
		opts.Args = args
	}
}

// WithNamedArgs adds args to the query.
func WithNamedArgs(args map[string]interface{}) QueryOption {
	return func(opts *queryOpts) {
		opts.NamedArgs = args
	}
}

// WithSchema returns a query option that adds the given table schema to the query.
func WithSchema(tbl TableSchema) QueryOption {
	return func(opts *queryOpts) {
		opts.Schema = tbl
	}
}

// WithResult sets the result receiver.
func WithResult(result interface{}) QueryOption {
	return func(opts *queryOpts) {
		opts.Result = result
	}
}

// WithDecodeConfig configures the DecodeConfig to use when calling DecodeStmt.
func WithDecodeConfig(cfg DecodeConfig) QueryOption {
	return func(opts *queryOpts) {
		opts.DecodeConfig = cfg
	}
}

// RunQuery executes the query stored in sql against the database opened in conn.
func RunQuery(ctx context.Context, conn *sqlite.Conn, sql string, modifiers ...QueryOption) error {
	args := queryOpts{
		DecodeConfig: DefaultDecodeConfig,
	}

	for _, fn := range modifiers {
		fn(&args)
	}

	opts := &sqlitex.ExecOptions{
		Args:  args.Args,
		Named: args.NamedArgs,
	}

	var (
		sliceVal    reflect.Value
		valElemType reflect.Type
	)

	if args.Result != nil {
		target := args.Result
		outVal := reflect.ValueOf(target)
		if outVal.Kind() != reflect.Ptr {
			return fmt.Errorf("target must be a pointer, got %T", target)
		}

		sliceVal = reflect.Indirect(outVal)
		if !sliceVal.IsValid() || sliceVal.IsNil() {
			newVal := reflect.Zero(outVal.Type().Elem())
			sliceVal.Set(newVal)
		}

		kind := sliceVal.Kind()
		if kind != reflect.Slice {
			return fmt.Errorf("target but be pointer to slice, got %T", target)
		}
		valType := sliceVal.Type()
		valElemType = valType.Elem()

		opts.ResultFunc = func(stmt *sqlite.Stmt) error {
			currentField := reflect.New(valElemType)

			if err := DecodeStmt(ctx, &args.Schema, stmt, currentField.Interface(), args.DecodeConfig); err != nil {
				resultDump := make(map[string]any)

				for colIdx := range stmt.ColumnCount() {
					name := stmt.ColumnName(colIdx)

					switch stmt.ColumnType(colIdx) { //nolint:exhaustive
					case sqlite.TypeText:
						resultDump[name] = stmt.ColumnText(colIdx)
					case sqlite.TypeFloat:
						resultDump[name] = stmt.ColumnFloat(colIdx)
					case sqlite.TypeInteger:
						resultDump[name] = stmt.ColumnInt(colIdx)
					case sqlite.TypeNull:
						resultDump[name] = "<null>"
					}
				}
				return fmt.Errorf("%w: %+v", err, resultDump)
			}

			sliceVal = reflect.Append(sliceVal, reflect.Indirect(currentField))

			return nil
		}
	}

	var err error
	if args.Transient {
		err = sqlitex.ExecuteTransient(conn, sql, opts)
	} else {
		err = sqlitex.Execute(conn, sql, opts)
	}
	if err != nil {
		return err
	}

	if args.Result != nil {
		reflect.Indirect(reflect.ValueOf(args.Result)).Set(sliceVal)
	}

	return nil
}
