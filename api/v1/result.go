// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"encoding/json"

	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	StatusFAIL     = "FAIL"
	StatusPASS     = "PASS"
	StatusSOFTFAIL = "SOFTFAIL"
	// StatusSKIP marks a material whose `when` condition evaluated to
	// false. Skipped materials do not count towards their parent's status.
	StatusSKIP = "SKIP"
)

type Results interface {
	GetStatus() string
}

// Assert reads the set's results and computes the finish date and the set
// status: FAIL when any policy or group failed, SKIP when the set has
// members and every one of them was skipped (nothing was verified), PASS
// otherwise. Skipped members never count against the set.
func (rs *ResultSet) Assert() error {
	rs.DateEnd = timestamppb.Now()
	members := 0
	skipped := 0
	for _, r := range rs.Results {
		members++
		switch r.GetStatus() {
		case StatusFAIL:
			rs.Status = StatusFAIL
			return nil
		case StatusSKIP:
			skipped++
		}
	}
	for _, r := range rs.Groups {
		members++
		switch r.GetStatus() {
		case StatusFAIL:
			rs.Status = StatusFAIL
			return nil
		case StatusSKIP:
			skipped++
		}
	}
	if members > 0 && skipped == members {
		rs.Status = StatusSKIP
		return nil
	}
	rs.Status = StatusPASS
	return nil
}

func (rs *ResultSet) MarshalJSON() ([]byte, error) {
	type Alias ResultSet
	var start, end string
	if rs.DateStart != nil {
		start = rs.DateStart.AsTime().Format("2006-01-02T15:04:05.000Z")
	}
	if rs.DateEnd != nil {
		end = rs.DateEnd.AsTime().Format("2006-01-02T15:04:05.000Z")
	}

	return json.Marshal(
		&struct {
			DateStart string `json:"date_start"`
			DateEnd   string `json:"date_end"`
			*Alias
		}{
			DateStart: start,
			DateEnd:   end,
			Alias:     (*Alias)(rs),
		},
	)
}

func (r *Result) MarshalJSON() ([]byte, error) {
	type Alias Result
	var start, end string
	if r.DateStart != nil {
		start = r.DateStart.AsTime().Format("2006-01-02T15:04:05.000Z")
	}
	if r.DateEnd != nil {
		end = r.DateEnd.AsTime().Format("2006-01-02T15:04:05.000Z")
	}

	return json.Marshal(
		&struct {
			DateStart string `json:"date_start"`
			DateEnd   string `json:"date_end"`
			*Alias
		}{
			DateStart: start,
			DateEnd:   end,
			Alias:     (*Alias)(r),
		},
	)
}

func (rg *ResultGroup) MarshalJSON() ([]byte, error) {
	type Alias ResultGroup
	var start, end string
	if rg.DateStart != nil {
		start = rg.DateStart.AsTime().Format("2006-01-02T15:04:05.000Z")
	}
	if rg.DateEnd != nil {
		end = rg.DateEnd.AsTime().Format("2006-01-02T15:04:05.000Z")
	}

	return json.Marshal(
		&struct {
			DateStart string `json:"date_start"`
			DateEnd   string `json:"date_end"`
			*Alias
		}{
			DateStart: start,
			DateEnd:   end,
			Alias:     (*Alias)(rg),
		},
	)
}

func (er *EvalResult) MarshalJSON() ([]byte, error) {
	type Alias EvalResult
	var date string
	if er.Date != nil {
		date = er.Date.AsTime().Format("2006-01-02T15:04:05.000Z")
	}
	return json.Marshal(
		&struct {
			Date string `json:"date"`
			*Alias
		}{
			Date:  date,
			Alias: (*Alias)(er),
		},
	)
}
