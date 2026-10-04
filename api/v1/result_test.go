// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestResultSetJSONRoundTrip ensures that a ResultSet marshaled with
// encoding/json (as ampel does when attesting) can be read back with
// protojson (as the predicate parsers do). Timestamps at every level must
// be rendered as RFC 3339 strings, not as {seconds, nanos} objects.
func TestResultSetJSONRoundTrip(t *testing.T) {
	t.Parallel()
	start := timestamppb.New(time.Date(2026, 9, 8, 2, 26, 26, 519000000, time.UTC))
	end := timestamppb.New(time.Date(2026, 9, 8, 2, 26, 27, 139000000, time.UTC))

	rs := &ResultSet{
		Status:    StatusFAIL,
		DateStart: start,
		DateEnd:   end,
		Results: []*Result{
			{
				Status:    StatusFAIL,
				DateStart: start,
				DateEnd:   end,
				EvalResults: []*EvalResult{
					{Status: StatusFAIL, Date: end},
				},
			},
		},
		Groups: []*ResultGroup{
			{
				Status:    StatusFAIL,
				DateStart: start,
				DateEnd:   end,
				Group:     &PolicyGroupRef{Id: "OSPS-AC-01"},
				EvalResults: []*BlockEvalResult{
					{
						Status: StatusFAIL,
						Results: []*Result{
							{Status: StatusFAIL, DateStart: start, DateEnd: end},
						},
					},
				},
				Error: "Evaluation failed by blocks [#0]",
			},
		},
	}

	data, err := json.Marshal(rs)
	require.NoError(t, err)

	// Every timestamp must have been rendered as a string
	var generic map[string]any
	require.NoError(t, json.Unmarshal(data, &generic))
	groups, ok := generic["groups"].([]any)
	require.True(t, ok)
	require.Len(t, groups, 1)
	group, ok := groups[0].(map[string]any)
	require.True(t, ok)
	require.IsType(t, "", group["date_start"])
	require.IsType(t, "", group["date_end"])

	// And protojson must be able to read the whole thing back
	parsed := &ResultSet{}
	require.NoError(t, protojson.Unmarshal(data, parsed))
	require.Len(t, parsed.GetGroups(), 1)
	require.Equal(t, start.AsTime(), parsed.GetGroups()[0].GetDateStart().AsTime())
	require.Equal(t, end.AsTime(), parsed.GetGroups()[0].GetDateEnd().AsTime())
	require.Equal(t, "OSPS-AC-01", parsed.GetGroups()[0].GetGroup().GetId())
	require.Equal(t, "Evaluation failed by blocks [#0]", parsed.GetGroups()[0].GetError())
	require.Equal(t, end.AsTime(), parsed.GetResults()[0].GetEvalResults()[0].GetDate().AsTime())
}

func TestResultSetAssertSkip(t *testing.T) {
	t.Parallel()
	res := func(status string) *Result { return &Result{Status: status} }
	grp := func(status string) *ResultGroup { return &ResultGroup{Status: status} }
	for _, tc := range []struct {
		name    string
		results []*Result
		groups  []*ResultGroup
		expect  string
	}{
		{"empty-set-passes", nil, nil, StatusPASS},
		{"all-pass", []*Result{res(StatusPASS), res(StatusPASS)}, nil, StatusPASS},
		{"skips-do-not-count", []*Result{res(StatusPASS), res(StatusSKIP)}, nil, StatusPASS},
		{"fail-wins-over-skip", []*Result{res(StatusSKIP), res(StatusFAIL)}, nil, StatusFAIL},
		{"softfail-passes", []*Result{res(StatusSOFTFAIL), res(StatusSKIP)}, nil, StatusPASS},
		{"all-policies-skipped", []*Result{res(StatusSKIP), res(StatusSKIP)}, nil, StatusSKIP},
		{"all-groups-skipped", nil, []*ResultGroup{grp(StatusSKIP)}, StatusSKIP},
		{"skipped-policies-passing-group", []*Result{res(StatusSKIP)}, []*ResultGroup{grp(StatusPASS)}, StatusPASS},
		{"skipped-policies-failing-group", []*Result{res(StatusSKIP)}, []*ResultGroup{grp(StatusFAIL)}, StatusFAIL},
		{"everything-skipped", []*Result{res(StatusSKIP)}, []*ResultGroup{grp(StatusSKIP)}, StatusSKIP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rs := &ResultSet{Results: tc.results, Groups: tc.groups}
			require.NoError(t, rs.Assert())
			require.Equal(t, tc.expect, rs.GetStatus())
			require.NotNil(t, rs.GetDateEnd())
		})
	}
}
