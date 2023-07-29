//go:build windows

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package netproxy

import (
	"syscall"
)

func SoMarkControl(c syscall.RawConn, mark int) error {
	return nil
}

func SoMark(fd int, mark int) error {
	return nil
}
