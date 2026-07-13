// Ported from service/netquery/query.go.
// Changes: package name, orm import path, removed HistoryDatabase and
// QueryActiveConnectionChartPayload (network-specific).
package filequery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/exp/slices"
	"zombiezen.com/go/sqlite"

	"github.com/safing/portmaster/service/filequery/orm"
)

// DatabaseName is a database name constant.
type DatabaseName string

// LiveDatabase is the only database used for file-access events.
const LiveDatabase = DatabaseName("main")

var charOnlyRegexp = regexp.MustCompile("[a-zA-Z]+")

// Collection of Query and Matcher types.
//
//nolint:golint
type (
	Query map[string][]Matcher

	MatchType interface {
		Operator() string
	}

	Equal interface{}

	Matcher struct {
		Equal          interface{}   `json:"$eq,omitempty"`
		NotEqual       interface{}   `json:"$ne,omitempty"`
		In             []interface{} `json:"$in,omitempty"`
		NotIn          []interface{} `json:"$notIn,omitempty"`
		Like           string        `json:"$like,omitempty"`
		Greater        *float64      `json:"$gt,omitempty"`
		GreaterOrEqual *float64      `json:"$ge,omitempty"`
		Less           *float64      `json:"$lt,omitempty"`
		LessOrEqual    *float64      `json:"$le,omitempty"`
	}

	Count struct {
		As       string `json:"as"`
		Field    string `json:"field"`
		Distinct bool   `json:"distinct"`
	}

	Sum struct {
		Condition Query  `json:"condition"`
		Field     string `json:"field"`
		As        string `json:"as"`
		Distinct  bool   `json:"distinct"`
	}

	Min struct {
		Condition *Query `json:"condition,omitempty"`
		Field     string `json:"field"`
		As        string `json:"as"`
		Distinct  bool   `json:"distinct"`
	}

	FieldSelect struct {
		Field string `json:"field"`
		As    string `json:"as"`
	}

	Select struct {
		Field       string       `json:"field"`
		FieldSelect *FieldSelect `json:"$field"`
		Count       *Count       `json:"$count,omitempty"`
		Sum         *Sum         `json:"$sum,omitempty"`
		Min         *Min         `json:"$min,omitempty"`
		Distinct    *string      `json:"$distinct,omitempty"`
	}

	Selects []Select

	TextSearch struct {
		Fields []string `json:"fields"`
		Value  string   `json:"value"`
	}

	OrderBy struct {
		Field string `json:"field"`
		Desc  bool   `json:"desc"`
	}

	OrderBys []OrderBy

	Pagination struct {
		PageSize int `json:"pageSize"`
		Page     int `json:"page"`
	}
)

// UnmarshalJSON unmarshals a Query from json.
func (query *Query) UnmarshalJSON(blob []byte) error {
	if *query == nil {
		*query = make(Query)
	}

	var model map[string]json.RawMessage
	if err := json.Unmarshal(blob, &model); err != nil {
		return err
	}

	for columnName, rawColumnQuery := range model {
		if len(rawColumnQuery) == 0 {
			continue
		}

		switch rawColumnQuery[0] {
		case '{':
			m, err := parseMatcher(rawColumnQuery)
			if err != nil {
				return err
			}
			(*query)[columnName] = []Matcher{*m}

		case '[':
			var rawMatchers []json.RawMessage
			if err := json.Unmarshal(rawColumnQuery, &rawMatchers); err != nil {
				return err
			}

			(*query)[columnName] = make([]Matcher, len(rawMatchers))
			for idx, val := range rawMatchers {
				if len(val) == 0 {
					continue
				}
				if val[0] == '{' {
					m, err := parseMatcher(val)
					if err != nil {
						return err
					}
					(*query)[columnName][idx] = *m
					continue
				} else if val[0] == '[' {
					return fmt.Errorf("invalid token [ in query for column %s", columnName)
				}
				var x interface{}
				if err := json.Unmarshal(val, &x); err != nil {
					return err
				}
				(*query)[columnName][idx] = Matcher{Equal: x}
			}

		default:
			var x interface{}
			if err := json.Unmarshal(rawColumnQuery, &x); err != nil {
				return err
			}
			(*query)[columnName] = []Matcher{{Equal: x}}
		}
	}

	return nil
}

func (page *Pagination) toSQLLimitOffsetClause() string {
	limit := page.PageSize
	if limit <= 0 || limit > 100 {
		limit = 100
	}

	sql := fmt.Sprintf("LIMIT %d", limit)
	if page.Page > 0 {
		sql += fmt.Sprintf(" OFFSET %d", page.Page*limit)
	}
	return sql
}

func parseMatcher(raw json.RawMessage) (*Matcher, error) {
	var m Matcher
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("invalid query matcher: %w", err)
	}
	return &m, nil
}

// Validate validates the matcher.
func (match Matcher) Validate() error {
	found := 0
	if match.Equal != nil {
		found++
	}
	if match.NotEqual != nil {
		found++
	}
	if match.In != nil {
		found++
	}
	if match.NotIn != nil {
		found++
	}
	if match.Like != "" {
		found++
	}
	if match.Greater != nil {
		found++
	}
	if match.GreaterOrEqual != nil {
		found++
	}
	if match.Less != nil {
		found++
	}
	if match.LessOrEqual != nil {
		found++
	}
	if found == 0 {
		return fmt.Errorf("no conditions specified")
	}
	return nil
}

func (text TextSearch) toSQLConditionClause(_ context.Context, schema *orm.TableSchema, suffix string, _ orm.EncodeConfig) (string, map[string]interface{}, error) {
	var (
		queryParts = make([]string, 0, len(text.Fields))
		params     = make(map[string]interface{})
	)

	key := fmt.Sprintf(":t%s", suffix)
	params[key] = fmt.Sprintf("%%%s%%", text.Value)

	for _, field := range text.Fields {
		colDef := schema.GetColumnDef(field)
		if colDef == nil {
			return "", nil, fmt.Errorf("column %s is not allowed in text-search", field)
		}
		if colDef.Type != sqlite.TypeText {
			return "", nil, fmt.Errorf("type of column %s cannot be used in text-search", colDef.Name)
		}
		queryParts = append(queryParts, fmt.Sprintf("%s LIKE %s", colDef.Name, key))
	}

	if len(queryParts) == 0 {
		return "", nil, nil
	}
	return "( " + strings.Join(queryParts, " OR ") + " )", params, nil
}

func (match Matcher) toSQLConditionClause(ctx context.Context, suffix string, conjunction string, colDef orm.ColumnDef, encoderConfig orm.EncodeConfig) (string, map[string]interface{}, error) {
	var (
		queryParts []string
		params     = make(map[string]interface{})
		errs       = new(multierror.Error)
		key        = fmt.Sprintf("%s%s", colDef.Name, suffix)
	)

	add := func(operator, suffix string, list bool, values ...interface{}) {
		var placeholder []string

		for idx, value := range values {
			var (
				encodedValue any
				err          error
			)

			kind := orm.NormalizeKind(reflect.TypeOf(value).Kind())
			isNumber := slices.Contains([]reflect.Kind{
				reflect.Uint,
				reflect.Int,
				reflect.Float64,
			}, kind)

			if colDef.IsTime && colDef.Type == sqlite.TypeText && isNumber {
				encodedValue = value
			} else {
				encodedValue, err = orm.EncodeValue(ctx, &colDef, value, encoderConfig)
				if err != nil {
					errs.Errors = append(errs.Errors,
						fmt.Errorf("failed to encode %v for column %s: %w", value, colDef.Name, err),
					)
					return
				}
			}

			uniqKey := fmt.Sprintf(":%s%s%d", key, suffix, idx)
			placeholder = append(placeholder, uniqKey)
			params[uniqKey] = encodedValue
		}

		nameStmt := colDef.Name

		if len(values) > 0 {
			kind := orm.NormalizeKind(reflect.TypeOf(values[0]).Kind())
			isNumber := slices.Contains([]reflect.Kind{
				reflect.Uint,
				reflect.Int,
				reflect.Float64,
			}, kind)

			if colDef.IsTime && colDef.Type == sqlite.TypeText && isNumber {
				nameStmt = fmt.Sprintf("strftime('%%s', %s)+0", nameStmt)
			}
		}

		if len(placeholder) == 1 && !list {
			queryParts = append(queryParts, fmt.Sprintf("%s %s %s", nameStmt, operator, placeholder[0]))
		} else {
			queryParts = append(queryParts, fmt.Sprintf("%s %s ( %s )", nameStmt, operator, strings.Join(placeholder, ", ")))
		}
	}

	if match.Equal != nil {
		add("=", "eq", false, match.Equal)
	}
	if match.NotEqual != nil {
		add("!=", "ne", false, match.NotEqual)
	}
	if match.In != nil {
		add("IN", "in", true, match.In...)
	}
	if match.NotIn != nil {
		add("NOT IN", "notin", true, match.NotIn...)
	}
	if match.Like != "" {
		add("LIKE", "like", false, match.Like)
	}
	if match.Greater != nil {
		add(">", "gt", false, *match.Greater)
	}
	if match.GreaterOrEqual != nil {
		add(">=", "ge", false, *match.GreaterOrEqual)
	}
	if match.Less != nil {
		add("<", "lt", false, *match.Less)
	}
	if match.LessOrEqual != nil {
		add("<=", "le", false, *match.LessOrEqual)
	}

	if len(queryParts) == 0 {
		return "( 1 = 1 )", nil, errs.ErrorOrNil()
	}
	if len(queryParts) == 1 {
		return queryParts[0], params, errs.ErrorOrNil()
	}
	return "( " + strings.Join(queryParts, " "+conjunction+" ") + " )", params, errs.ErrorOrNil()
}

func (query Query) toSQLWhereClause(ctx context.Context, suffix string, m *orm.TableSchema, encoderConfig orm.EncodeConfig) (string, map[string]interface{}, error) {
	if len(query) == 0 {
		return "", nil, nil
	}

	lm := make(map[string]orm.ColumnDef, len(m.Columns))
	for _, col := range m.Columns {
		lm[col.Name] = col
	}

	paramMap := make(map[string]interface{})
	columnStmts := make([]string, 0, len(query))

	queryKeys := make([]string, 0, len(query))
	for column := range query {
		queryKeys = append(queryKeys, column)
	}
	sort.Strings(queryKeys)

	errs := new(multierror.Error)
	for _, column := range queryKeys {
		values := query[column]
		colDef, ok := lm[column]
		if !ok {
			errs.Errors = append(errs.Errors, fmt.Errorf("column %s is not allowed", column))
			continue
		}

		queryParts := make([]string, len(values))
		for idx, val := range values {
			matcherQuery, params, err := val.toSQLConditionClause(ctx, fmt.Sprintf("%s%d", suffix, idx), "AND", colDef, encoderConfig)
			if err != nil {
				errs.Errors = append(errs.Errors,
					fmt.Errorf("invalid matcher at index %d for column %s: %w", idx, colDef.Name, err),
				)
				continue
			}
			for key, val := range params {
				if _, ok := paramMap[key]; ok {
					panic("sqlite parameter collision")
				}
				paramMap[key] = val
			}
			queryParts[idx] = matcherQuery
		}
		columnStmts = append(columnStmts, fmt.Sprintf("( %s )", strings.Join(queryParts, " OR ")))
	}

	return strings.Join(columnStmts, " AND "), paramMap, errs.ErrorOrNil()
}

// UnmarshalJSON unmarshals a Selects from json.
func (sel *Selects) UnmarshalJSON(blob []byte) error {
	if len(blob) == 0 {
		return io.ErrUnexpectedEOF
	}
	if blob[0] == '[' {
		var result []Select
		if err := json.Unmarshal(blob, &result); err != nil {
			return err
		}
		*sel = result
		return nil
	}
	if blob[0] == '{' {
		var result Select
		if err := json.Unmarshal(blob, &result); err != nil {
			return err
		}
		*sel = []Select{result}
		return nil
	}
	var field string
	if err := json.Unmarshal(blob, &field); err != nil {
		return err
	}
	return nil
}

// UnmarshalJSON unmarshals a Select from json.
func (sel *Select) UnmarshalJSON(blob []byte) error {
	if len(blob) == 0 {
		return io.ErrUnexpectedEOF
	}
	if blob[0] == '{' {
		var res struct {
			Field       string       `json:"field"`
			Count       *Count       `json:"$count"`
			Sum         *Sum         `json:"$sum"`
			Min         *Min         `json:"$min"`
			Distinct    *string      `json:"$distinct"`
			FieldSelect *FieldSelect `json:"$field"`
		}
		if err := json.Unmarshal(blob, &res); err != nil {
			return err
		}
		sel.Count = res.Count
		sel.Field = res.Field
		sel.FieldSelect = res.FieldSelect
		sel.Distinct = res.Distinct
		sel.Sum = res.Sum
		sel.Min = res.Min

		if sel.Count != nil && sel.Count.As != "" && !charOnlyRegexp.MatchString(sel.Count.As) {
			return fmt.Errorf("invalid characters in $count.as, value must match [a-zA-Z]+")
		}
		if sel.Sum != nil && sel.Sum.As != "" && !charOnlyRegexp.MatchString(sel.Sum.As) {
			return fmt.Errorf("invalid characters in $sum.as, value must match [a-zA-Z]+")
		}
		if sel.Min != nil && sel.Min.As != "" && !charOnlyRegexp.MatchString(sel.Min.As) {
			return fmt.Errorf("invalid characters in $min.as, value must match [a-zA-Z]+")
		}
		if sel.FieldSelect != nil && sel.FieldSelect.As != "" && !charOnlyRegexp.MatchString(sel.FieldSelect.As) {
			return fmt.Errorf("invalid characters in $field.as, value must match [a-zA-Z]+")
		}
		return nil
	}
	var x string
	if err := json.Unmarshal(blob, &x); err != nil {
		return err
	}
	sel.Field = x
	return nil
}

// UnmarshalJSON unmarshals OrderBys from json.
func (orderBys *OrderBys) UnmarshalJSON(blob []byte) error {
	if len(blob) == 0 {
		return io.ErrUnexpectedEOF
	}
	if blob[0] == '[' {
		var result []OrderBy
		if err := json.Unmarshal(blob, &result); err != nil {
			return err
		}
		*orderBys = result
		return nil
	}
	if blob[0] == '{' {
		var result OrderBy
		if err := json.Unmarshal(blob, &result); err != nil {
			return err
		}
		*orderBys = []OrderBy{result}
		return nil
	}
	var field string
	if err := json.Unmarshal(blob, &field); err != nil {
		return err
	}
	*orderBys = []OrderBy{{Field: field, Desc: false}}
	return nil
}

// UnmarshalJSON unmarshals an OrderBy from json.
func (orderBy *OrderBy) UnmarshalJSON(blob []byte) error {
	if len(blob) == 0 {
		return io.ErrUnexpectedEOF
	}
	if blob[0] == '{' {
		var res struct {
			Field string `json:"field"`
			Desc  bool   `json:"desc"`
		}
		if err := json.Unmarshal(blob, &res); err != nil {
			return err
		}
		orderBy.Desc = res.Desc
		orderBy.Field = res.Field
		return nil
	}
	var field string
	if err := json.Unmarshal(blob, &field); err != nil {
		return err
	}
	orderBy.Field = field
	orderBy.Desc = false
	return nil
}
