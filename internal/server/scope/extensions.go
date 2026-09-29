package scope

import "path"

func IsUninterestingPath(uriPath string) bool {
	extension := path.Ext(uriPath)
	if _, ok := excludedExtensions[extension]; ok {
		return true
	}
	return false
}

var excludedExtensions = map[string]struct{}{
	".jpg": {}, ".jpeg": {}, ".png": {}, ".gif": {}, ".bmp": {}, ".tiff": {}, ".ico": {},
	".mp4": {}, ".avi": {}, ".mov": {}, ".wmv": {}, ".flv": {}, ".mkv": {}, ".webm": {},
	".mp3": {}, ".wav": {}, ".aac": {}, ".flac": {}, ".ogg": {}, ".wma": {},
	".zip": {}, ".rar": {}, ".7z": {}, ".tar": {}, ".gz": {}, ".bz2": {},
	".exe": {}, ".bin": {}, ".iso": {}, ".img": {},
	".doc": {}, ".docx": {}, ".xls": {}, ".xlsx": {}, ".ppt": {}, ".pptx": {},
	".pdf": {}, ".psd": {}, ".ai": {}, ".eps": {}, ".indd": {},
	".swf": {}, ".fla": {}, ".css": {}, ".scss": {}, ".less": {},
	".js": {}, ".ts": {}, ".jsx": {}, ".tsx": {},
	".xml": {}, ".json": {}, ".yaml": {}, ".yml": {},
	".csv": {}, ".txt": {}, ".log": {}, ".md": {},
	".ttf": {}, ".otf": {}, ".woff": {}, ".woff2": {}, ".eot": {},
	".svg": {}, ".svgz": {}, ".webp": {}, ".tif": {},
	".mpg": {}, ".mpeg": {}, ".weba": {},
	".m4a": {}, ".m4v": {}, ".3gp": {}, ".3g2": {},
	".ogv": {}, ".ogm": {}, ".oga": {}, ".ogx": {},
	".srt": {}, ".min.js": {}, ".min.css": {}, ".js.map": {},
	".min.js.map": {}, ".chunk.css.map": {}, ".hub.js.map": {},
	".hub.css.map": {}, ".map": {},
}
