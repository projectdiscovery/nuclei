package handlers

import (
	"strconv"

	"github.com/labstack/echo/v4"
)

const (
	defaultPage = int32(0)
	defaultSize = int32(10)
)

// paginationDataFromContext returns page and size for context
func paginationDataFromContext(ctx echo.Context) (int32, int32) {
	pageInt, sizeInt := int32(defaultPage), int32(defaultSize)

	if page := ctx.QueryParam("page"); page != "" {
		pageValue, _ := strconv.ParseInt(page, 10, 32)
		pageInt = int32(pageValue)
	}
	if size := ctx.QueryParam("size"); size != "" {
		sizeValue, _ := strconv.ParseInt(size, 10, 32)
		sizeInt = int32(sizeValue)
	}
	return pageInt, sizeInt
}
