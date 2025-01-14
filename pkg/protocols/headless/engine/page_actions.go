package engine

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/proto"
	"github.com/go-rod/rod/lib/utils"
	"github.com/kitabisa/go-ci"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
	protocolutils "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	httputil "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils/http"
	contextutil "github.com/projectdiscovery/utils/context"
	"github.com/projectdiscovery/utils/errkit"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/segmentio/ksuid"
)

var (
	errinvalidArguments = errorutil.New("invalid arguments provided")
	ErrLFAccessDenied   = errorutil.New("Use -allow-local-file-access flag to enable local file access")
	// ErrActionExecDealine is the error returned when alloted time for action execution exceeds
	ErrActionExecDealine = errkit.New("headless action execution deadline exceeded").SetKind(errkit.ErrKindDeadline).Build()
)

const (
	errCouldNotGetElement  = "could not get element"
	errCouldNotScroll      = "could not scroll into view"
	errElementDidNotAppear = "Element did not appear in the given amount of time"
)

// ExecuteActions executes a list of actions on a page.
func (p *Page) ExecuteActions(input *contextargs.Context, actions []*Action, variables map[string]interface{}) (outData ActionData, err error) {
	outData = make(ActionData)
	// waitFuncs are function that needs to be executed after navigation
	// typically used for waitEvent
	waitFuncs := make([]func() error, 0)

	// avoid any future panics caused due to go-rod library
	// TODO(dwisiswant0): remove this once we get the RCA.
	defer func() {
		if ci.IsCI() {
			return
		}

		if r := recover(); r != nil {
			err = errorutil.New("panic on headless action: %v", r)
		}
	}()

	for _, act := range actions {
		switch act.ActionType.ActionType {
		case ActionNavigate:
			err = p.NavigateURL(act, outData, variables)
			if err == nil {
				// if navigation successful trigger all waitFuncs (if any)
				for _, waitFunc := range waitFuncs {
					if waitFunc != nil {
						if err := waitFunc(); err != nil {
							return nil, errorutil.NewWithErr(err).Msgf("error occurred while executing waitFunc")
						}
					}
				}
			}
		case ActionScript:
			err = p.RunScript(act, outData)
		case ActionClick:
			err = p.ClickElement(act, outData)
		case ActionRightClick:
			err = p.RightClickElement(act, outData)
		case ActionTextInput:
			err = p.InputElement(act, outData)
		case ActionScreenshot:
			err = p.Screenshot(act, outData)
		case ActionTimeInput:
			err = p.TimeInputElement(act, outData)
		case ActionSelectInput:
			err = p.SelectInputElement(act, outData)
		case ActionWaitDOM:
			event := proto.PageLifecycleEventNameDOMContentLoaded
			err = p.WaitPageLifecycleEvent(act, outData, event)
		case ActionWaitFCP:
			event := proto.PageLifecycleEventNameFirstContentfulPaint
			err = p.WaitPageLifecycleEvent(act, outData, event)
		case ActionWaitFMP:
			event := proto.PageLifecycleEventNameFirstMeaningfulPaint
			err = p.WaitPageLifecycleEvent(act, outData, event)
		case ActionWaitIdle:
			event := proto.PageLifecycleEventNameNetworkIdle
			err = p.WaitPageLifecycleEvent(act, outData, event)
		case ActionWaitLoad:
			event := proto.PageLifecycleEventNameLoad
			err = p.WaitPageLifecycleEvent(act, outData, event)
		case ActionWaitStable:
			err = p.WaitStable(act, outData)
		// NOTE(dwisiswant0): Mapping `ActionWaitLoad` to `Page.WaitStable`,
		// just in case waiting for the `proto.PageLifecycleEventNameLoad` event
		// doesn't meet expectations.
		// case ActionWaitLoad, ActionWaitStable:
		// 	err = p.WaitStable(act, outData)
		case ActionGetResource:
			err = p.GetResource(act, outData)
		case ActionExtract:
			err = p.ExtractElement(act, outData)
		case ActionWaitEvent:
			var waitFunc func() error
			waitFunc, err = p.WaitEvent(act, outData)
			if waitFunc != nil {
				waitFuncs = append(waitFuncs, waitFunc)
			}
		case ActionWaitDialog:
			err = p.HandleDialog(act, outData)
		case ActionFilesInput:
			if p.options.Options.AllowLocalFileAccess {
				err = p.FilesInput(act, outData)
			} else {
				err = ErrLFAccessDenied
			}
		case ActionAddHeader:
			err = p.ActionAddHeader(act, outData)
		case ActionSetHeader:
			err = p.ActionSetHeader(act, outData)
		case ActionDeleteHeader:
			err = p.ActionDeleteHeader(act, outData)
		case ActionSetBody:
			err = p.ActionSetBody(act, outData)
		case ActionSetMethod:
			err = p.ActionSetMethod(act, outData)
		case ActionKeyboard:
			err = p.KeyboardAction(act, outData)
		case ActionDebug:
			err = p.DebugAction(act, outData)
		case ActionSleep:
			err = p.SleepAction(act, outData)
		case ActionWaitVisible:
			err = p.WaitVisible(act, outData)
		default:
			continue
		}
		if err != nil {
			return nil, errors.Wrap(err, "error occurred executing action")
		}
	}
	return outData, nil
}

type rule struct {
	*sync.Once
	Action ActionType
	Part   string
	Args   map[string]string
}

// WaitVisible waits until an element appears.
func (p *Page) WaitVisible(act *Action, out ActionData) error {
	timeout, err := getTimeout(p, act)
	if err != nil {
		return errors.Wrap(err, "Wrong timeout given")
	}

	pollTime, err := getPollTime(p, act)
	if err != nil {
		return errors.Wrap(err, "Wrong polling time given")
	}

	element, _ := p.Sleeper(pollTime, timeout).
		Timeout(timeout).
		pageElementBy(act.Data)

	if element != nil {
		if err := element.WaitVisible(); err != nil {
			return errors.Wrap(err, errElementDidNotAppear)
		}
	} else {
		return errors.New(errElementDidNotAppear)
	}

	return nil
}

func (p *Page) Sleeper(pollTimeout, timeout time.Duration) *Page {
	page := *p
	page.page = page.Page().Sleeper(func() utils.Sleeper {
		return createBackOffSleeper(pollTimeout, timeout)
	})
	return &page
}

func (p *Page) Timeout(timeout time.Duration) *Page {
	page := *p
	page.page = page.Page().Timeout(timeout)
	return &page
}

func createBackOffSleeper(pollTimeout, timeout time.Duration) utils.Sleeper {
	backoffSleeper := utils.BackoffSleeper(pollTimeout, timeout, func(duration time.Duration) time.Duration {
		return duration
	})

	return func(ctx context.Context) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		return backoffSleeper(ctx)
	}
}

func getNavigationFunc(p *Page, act *Action, event proto.PageLifecycleEventName) (func(), error) {
	dur, err := getTimeout(p, act)
	if err != nil {
		return nil, errors.Wrap(err, "Wrong timeout given")
	}

	fn := p.page.Timeout(dur).WaitNavigation(event)

	return fn, nil
}

func getTimeout(p *Page, act *Action) (time.Duration, error) {
	return geTimeParameter(p, act, "timeout", 3, time.Second)
}

func getPollTime(p *Page, act *Action) (time.Duration, error) {
	return geTimeParameter(p, act, "pollTime", 100, time.Millisecond)
}

func geTimeParameter(p *Page, act *Action, parameterName string, defaultValue time.Duration, duration time.Duration) (time.Duration, error) {
	pollTimeString := p.getActionArgWithDefaultValues(act, parameterName)
	if pollTimeString == "" {
		return defaultValue * duration, nil
	}
	timeout, err := strconv.Atoi(pollTimeString)
	if err != nil {
		return time.Duration(0), err
	}
	return time.Duration(timeout) * duration, nil
}

// ActionAddHeader executes a AddHeader action.
func (p *Page) ActionAddHeader(act *Action, out ActionData) error {
	in := p.getActionArgWithDefaultValues(act, "part")

	args := make(map[string]string)
	args["key"] = p.getActionArgWithDefaultValues(act, "key")
	args["value"] = p.getActionArgWithDefaultValues(act, "value")
	p.rules = append(p.rules, rule{Action: ActionAddHeader, Part: in, Args: args})
	return nil
}

// ActionSetHeader executes a SetHeader action.
func (p *Page) ActionSetHeader(act *Action, out ActionData) error {
	in := p.getActionArgWithDefaultValues(act, "part")

	args := make(map[string]string)
	args["key"] = p.getActionArgWithDefaultValues(act, "key")
	args["value"] = p.getActionArgWithDefaultValues(act, "value")
	p.rules = append(p.rules, rule{Action: ActionSetHeader, Part: in, Args: args})
	return nil
}

// ActionDeleteHeader executes a DeleteHeader action.
func (p *Page) ActionDeleteHeader(act *Action, out ActionData) error {
	in := p.getActionArgWithDefaultValues(act, "part")

	args := make(map[string]string)
	args["key"] = p.getActionArgWithDefaultValues(act, "key")
	p.rules = append(p.rules, rule{Action: ActionDeleteHeader, Part: in, Args: args})
	return nil
}

// ActionSetBody executes a SetBody action.
func (p *Page) ActionSetBody(act *Action, out ActionData) error {
	in := p.getActionArgWithDefaultValues(act, "part")

	args := make(map[string]string)
	args["body"] = p.getActionArgWithDefaultValues(act, "body")
	p.rules = append(p.rules, rule{Action: ActionSetBody, Part: in, Args: args})
	return nil
}

// ActionSetMethod executes an SetMethod action.
func (p *Page) ActionSetMethod(act *Action, out ActionData) error {
	in := p.getActionArgWithDefaultValues(act, "part")

	args := make(map[string]string)
	args["method"] = p.getActionArgWithDefaultValues(act, "method")
	p.rules = append(p.rules, rule{Action: ActionSetMethod, Part: in, Args: args, Once: &sync.Once{}})
	return nil
}

// NavigateURL executes an ActionLoadURL actions loading a URL for the page.
func (p *Page) NavigateURL(action *Action, out ActionData, allvars map[string]interface{}) error {
	// input <- is input url from cli
	// target <- is the url from template (ex: {{BaseURL}}/test)
	input, err := urlutil.Parse(p.input.MetaInput.Input)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not parse url %s", p.input.MetaInput.Input)
	}
	target := p.getActionArgWithDefaultValues(action, "url")
	if target == "" {
		return errinvalidArguments
	}

	// if target contains port ex: {{BaseURL}}:8080 use port specified in input
	input, target = httputil.UpdateURLPortFromPayload(input, target)
	hasTrailingSlash := httputil.HasTrailingSlash(target)

	// create vars from input url
	defaultReqVars := protocolutils.GenerateVariables(input, hasTrailingSlash, contextargs.GenerateVariables(p.input))
	// merge all variables
	// Note: ideally we should evaluate all available variables with reqvars
	// but due to cyclic dependency between packages `engine` and `protocols`
	// allvars are evaluated,merged and passed from headless package itself
	// TODO: remove cyclic dependency between packages `engine` and `protocols`
	allvars = generators.MergeMaps(allvars, defaultReqVars)

	if vardump.EnableVarDump {
		gologger.Debug().Msgf("Headless Protocol request variables: %s\n", vardump.DumpVariables(allvars))
	}

	// Evaluate the target url with all variables
	target, err = expressions.Evaluate(target, allvars)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not evaluate url %s", target)
	}

	reqURL, err := urlutil.ParseURL(target, true)
	if err != nil {
		return errorutil.NewWithTag("http", "failed to parse url %v while creating http request", target)
	}

	// ===== parameter automerge =====
	// while merging parameters first preference is given to target params
	finalparams := input.Params.Clone()
	finalparams.Merge(reqURL.Params.Encode())
	reqURL.Params = finalparams

	// log all navigated requests
	p.instance.requestLog[action.GetArg("url")] = reqURL.String()

	if err := p.page.Navigate(reqURL.String()); err != nil {
		return errorutil.NewWithErr(err).Msgf("could not navigate to url %s", reqURL.String())
	}
	return nil
}

// RunScript runs a script on the loaded page
func (p *Page) RunScript(action *Action, out ActionData) error {
	code := p.getActionArgWithDefaultValues(action, "code")
	if code == "" {
		return errinvalidArguments
	}
	if p.getActionArgWithDefaultValues(action, "hook") == "true" {
		if _, err := p.page.EvalOnNewDocument(code); err != nil {
			return err
		}
	}
	data, err := p.page.Eval(code)
	if err != nil {
		return err
	}
	if data != nil && action.Name != "" {
		out[action.Name] = data.Value.String()
	}
	return nil
}

// ClickElement executes click actions for an element.
func (p *Page) ClickElement(act *Action, out ActionData) error {
	element, err := p.pageElementBy(act.Data)
	if err != nil {
		return errors.Wrap(err, errCouldNotGetElement)
	}
	if err = element.ScrollIntoView(); err != nil {
		return errors.Wrap(err, errCouldNotScroll)
	}
	if err = element.Click(proto.InputMouseButtonLeft, 1); err != nil {
		return errors.Wrap(err, "could not click element")
	}
	return nil
}

// KeyboardAction executes a keyboard action on the page.
func (p *Page) KeyboardAction(act *Action, out ActionData) error {
	return p.page.Keyboard.Type([]input.Key(p.getActionArgWithDefaultValues(act, "keys"))...)
}

// RightClickElement executes right click actions for an element.
func (p *Page) RightClickElement(act *Action, out ActionData) error {
	element, err := p.pageElementBy(act.Data)
	if err != nil {
		return errors.Wrap(err, errCouldNotGetElement)
	}
	if err = element.ScrollIntoView(); err != nil {
		return errors.Wrap(err, errCouldNotScroll)
	}
	if err = element.Click(proto.InputMouseButtonRight, 1); err != nil {
		return errors.Wrap(err, "could not right click element")
	}
	return nil
}

// Screenshot executes screenshot action on a page
func (p *Page) Screenshot(act *Action, out ActionData) error {
	to := p.getActionArgWithDefaultValues(act, "to")
	if to == "" {
		to = ksuid.New().String()
		if act.Name != "" {
			out[act.Name] = to
		}
	}
	var data []byte
	var err error
	if p.getActionArgWithDefaultValues(act, "fullpage") == "true" {
		data, err = p.page.Screenshot(true, &proto.PageCaptureScreenshot{})
	} else {
		data, err = p.page.Screenshot(false, &proto.PageCaptureScreenshot{})
	}
	if err != nil {
		return errors.Wrap(err, "could not take screenshot")
	}
	targetPath := p.getActionArgWithDefaultValues(act, "to")
	targetPath, err = fileutil.CleanPath(targetPath)
	if err != nil {
		return errorutil.New("could not clean output screenshot path %s", targetPath)
	}
	// allow if targetPath is child of current working directory
	if !protocolstate.IsLFAAllowed() {
		cwd, err := os.Getwd()
		if err != nil {
			return errorutil.NewWithErr(err).Msgf("could not get current working directory")
		}
		if !strings.HasPrefix(targetPath, cwd) {
			// writing outside of cwd requires -lfa flag
			return ErrLFAccessDenied
		}
	}

	// edgecase create directory if mkdir=true and path contains directory
	if p.getActionArgWithDefaultValues(act, "mkdir") == "true" && stringsutil.ContainsAny(to, folderutil.UnixPathSeparator, folderutil.WindowsPathSeparator) {
		// creates new directory if needed based on path `to`
		// TODO: replace all permission bits with fileutil constants (https://github.com/projectdiscovery/utils/issues/113)
		if err := os.MkdirAll(filepath.Dir(to), 0700); err != nil {
			return errorutil.NewWithErr(err).Msgf("failed to create directory while writing screenshot")
		}
	}

	// actual file path to write
	filePath := targetPath
	if !strings.HasSuffix(filePath, ".png") {
		filePath += ".png"
	}

	if fileutil.FileExists(filePath) {
		// return custom error as overwriting files is not supported
		return errorutil.NewWithTag("screenshot", "failed to write screenshot, file %v already exists", filePath)
	}
	err = os.WriteFile(filePath, data, 0540)
	if err != nil {
		return errors.Wrap(err, "could not write screenshot")
	}
	gologger.Info().Msgf("Screenshot successfully saved at %v\n", filePath)
	return nil
}

// InputElement executes input element actions for an element.
func (p *Page) InputElement(act *Action, out ActionData) error {
	value := p.getActionArgWithDefaultValues(act, "value")
	if value == "" {
		return errinvalidArguments
	}
	element, err := p.pageElementBy(act.Data)
	if err != nil {
		return errors.Wrap(err, errCouldNotGetElement)
	}
	if err = element.ScrollIntoView(); err != nil {
		return errors.Wrap(err, errCouldNotScroll)
	}
	if err = element.Input(value); err != nil {
		return errors.Wrap(err, "could not input element")
	}
	return nil
}

// TimeInputElement executes time input on an element
func (p *Page) TimeInputElement(act *Action, out ActionData) error {
	value := p.getActionArgWithDefaultValues(act, "value")
	if value == "" {
		return errinvalidArguments
	}
	element, err := p.pageElementBy(act.Data)
	if err != nil {
		return errors.Wrap(err, errCouldNotGetElement)
	}
	if err = element.ScrollIntoView(); err != nil {
		return errors.Wrap(err, errCouldNotScroll)
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return errors.Wrap(err, "could not parse time")
	}
	if err := element.InputTime(t); err != nil {
		return errors.Wrap(err, "could not input element")
	}
	return nil
}

// SelectInputElement executes select input statement action on a element
func (p *Page) SelectInputElement(act *Action, out ActionData) error {
	value := p.getActionArgWithDefaultValues(act, "value")
	if value == "" {
		return errinvalidArguments
	}
	element, err := p.pageElementBy(act.Data)
	if err != nil {
		return errors.Wrap(err, errCouldNotGetElement)
	}
	if err = element.ScrollIntoView(); err != nil {
		return errors.Wrap(err, errCouldNotScroll)
	}

	selectedBool := false
	if p.getActionArgWithDefaultValues(act, "selected") == "true" {
		selectedBool = true
	}
	by := p.getActionArgWithDefaultValues(act, "selector")
	if err := element.Select([]string{value}, selectedBool, selectorBy(by)); err != nil {
		return errors.Wrap(err, "could not select input")
	}
	return nil
}

// WaitPageLifecycleEvent waits for specified page lifecycle event name
func (p *Page) WaitPageLifecycleEvent(act *Action, out ActionData, event proto.PageLifecycleEventName) error {
	fn, err := getNavigationFunc(p, act, event)
	if err != nil {
		return err
	}

	fn()

	return nil
}

// WaitStable waits until the page is stable
func (p *Page) WaitStable(act *Action, out ActionData) error {
	var dur time.Duration = time.Second // default stable page duration: 1s

	timeout, err := getTimeout(p, act)
	if err != nil {
		return errors.Wrap(err, "Wrong timeout given")
	}

	argDur := act.Data["duration"]
	if argDur != "" {
		dur, err = time.ParseDuration(argDur)
		if err != nil {
			dur = time.Second
		}
	}

	return p.page.Timeout(timeout).WaitStable(dur)
}

// GetResource gets a resource from an element from page.
func (p *Page) GetResource(act *Action, out ActionData) error {
	element, err := p.pageElementBy(act.Data)
	if err != nil {
		return errors.Wrap(err, errCouldNotGetElement)
	}
	resource, err := element.Resource()
	if err != nil {
		return errors.Wrap(err, "could not get src for element")
	}
	if act.Name != "" {
		out[act.Name] = string(resource)
	}
	return nil
}

// FilesInput acts with a file input element on page
func (p *Page) FilesInput(act *Action, out ActionData) error {
	element, err := p.pageElementBy(act.Data)
	if err != nil {
		return errors.Wrap(err, errCouldNotGetElement)
	}
	if err = element.ScrollIntoView(); err != nil {
		return errors.Wrap(err, errCouldNotScroll)
	}
	value := p.getActionArgWithDefaultValues(act, "value")
	filesPaths := strings.Split(value, ",")
	if err := element.SetFiles(filesPaths); err != nil {
		return errors.Wrap(err, "could not set files")
	}
	return nil
}

// ExtractElement extracts from an element on the page.
func (p *Page) ExtractElement(act *Action, out ActionData) error {
	element, err := p.pageElementBy(act.Data)
	if err != nil {
		return errors.Wrap(err, errCouldNotGetElement)
	}
	if err = element.ScrollIntoView(); err != nil {
		return errors.Wrap(err, errCouldNotScroll)
	}
	switch p.getActionArgWithDefaultValues(act, "target") {
	case "attribute":
		attrName := p.getActionArgWithDefaultValues(act, "attribute")
		if attrName == "" {
			return errors.New("attribute can't be empty")
		}
		attrValue, err := element.Attribute(attrName)
		if err != nil {
			return errors.Wrap(err, "could not get attribute")
		}
		if act.Name != "" {
			out[act.Name] = *attrValue
		}
	default:
		text, err := element.Text()
		if err != nil {
			return errors.Wrap(err, "could not get element text node")
		}
		if act.Name != "" {
			out[act.Name] = text
		}
	}
	return nil
}

// WaitEvent waits for an event to happen on the page.
func (p *Page) WaitEvent(act *Action, out ActionData) (func() error, error) {
	event := p.getActionArgWithDefaultValues(act, "event")
	if event == "" {
		return nil, errors.New("event not recognized")
	}

	var waitEvent proto.Event
	gotType := proto.GetType(event)
	if gotType == nil {
		return nil, errorutil.New("event %v does not exist", event)
	}
	tmp, ok := reflect.New(gotType).Interface().(proto.Event)
	if !ok {
		return nil, errorutil.New("event %v is not a page event", event)
	}
	waitEvent = tmp
	maxDuration := 10 * time.Second // 10 sec is max wait duration for any event

	// allow user to specify max-duration for wait-event
	if value := p.getActionArgWithDefaultValues(act, "max-duration"); value != "" {
		var err error
		maxDuration, err = time.ParseDuration(value)
		if err != nil {
			return nil, errorutil.NewWithErr(err).Msgf("could not parse max-duration")
		}
	}

	// Just wait the event to happen
	waitFunc := func() (err error) {
		// execute actual wait event
		ctx, cancel := context.WithTimeoutCause(context.Background(), maxDuration, ErrActionExecDealine)
		defer cancel()
		err = contextutil.ExecFunc(ctx, p.page.WaitEvent(waitEvent))
		return
	}
	return waitFunc, nil
}

// HandleDialog handles JavaScript dialog (alert, confirm, prompt, or onbeforeunload).
func (p *Page) HandleDialog(act *Action, out ActionData) error {
	maxDuration := 10 * time.Second

	if dur := p.getActionArgWithDefaultValues(act, "max-duration"); dur != "" {
		var err error

		maxDuration, err = time.ParseDuration(dur)
		if err != nil {
			return errorutil.NewWithErr(err).Msgf("could not parse max-duration")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), maxDuration)
	defer cancel()

	wait, handle := p.page.HandleDialog()
	fn := func() (*proto.PageJavascriptDialogOpening, error) {
		dialog := wait()
		err := handle(&proto.PageHandleJavaScriptDialog{
			Accept:     true,
			PromptText: "",
		})

		return dialog, err
	}

	dialog, err := contextutil.ExecFuncWithTwoReturns(ctx, fn)
	if err == nil && act.Name != "" {
		out[act.Name] = true
		out[act.Name+"_type"] = string(dialog.Type)
		out[act.Name+"_message"] = dialog.Message
	}

	return nil
}

// pageElementBy returns a page element from a variety of inputs.
//
// Supported values for by: r -> selector & regex, x -> xpath, js -> eval js,
// search => query, default ("") => selector.
func (p *Page) pageElementBy(data map[string]string) (*rod.Element, error) {
	by, ok := data["by"]
	if !ok {
		by = ""
	}
	page := p.page

	switch by {
	case "r", "regex":
		return page.ElementR(data["selector"], data["regex"])
	case "x", "xpath":
		return page.ElementX(data["xpath"])
	case "js":
		return page.ElementByJS(&rod.EvalOptions{JS: data["js"]})
	case "search":
		elms, err := page.Search(data["query"])
		if err != nil {
			return nil, err
		}

		if elms.First != nil {
			return elms.First, nil
		}
		return nil, errors.New("no such element")
	default:
		return page.Element(data["selector"])
	}
}

// DebugAction enables debug action on a page.
func (p *Page) DebugAction(act *Action, out ActionData) error {
	p.instance.browser.engine.SlowMotion(5 * time.Second)
	p.instance.browser.engine.Trace(true)
	return nil
}

// SleepAction sleeps on the page for a specified duration
func (p *Page) SleepAction(act *Action, out ActionData) error {
	seconds := act.Data["duration"]
	if seconds == "" {
		seconds = "5"
	}
	parsed, err := strconv.Atoi(seconds)
	if err != nil {
		return err
	}
	time.Sleep(time.Duration(parsed) * time.Second)
	return nil
}

// selectorBy returns a selector from a representation.
func selectorBy(selector string) rod.SelectorType {
	switch selector {
	case "r":
		return rod.SelectorTypeRegex
	case "css":
		return rod.SelectorTypeCSSSector
	case "regex":
		return rod.SelectorTypeRegex
	default:
		return rod.SelectorTypeText
	}
}

func (p *Page) getActionArgWithDefaultValues(action *Action, arg string) string {
	return p.getActionArgWithValues(action, arg, generators.MergeMaps(
		generators.BuildPayloadFromOptions(p.instance.browser.options),
		p.payloads,
	))
}

func (p *Page) getActionArgWithValues(action *Action, arg string, values map[string]interface{}) string {
	argValue := action.GetArg(arg)
	argValue = replaceWithValues(argValue, values)
	if p.instance.interactsh != nil {
		var interactshURLs []string
		argValue, interactshURLs = p.instance.interactsh.Replace(argValue, p.InteractshURLs)
		p.addInteractshURL(interactshURLs...)
	}
	return argValue
}
