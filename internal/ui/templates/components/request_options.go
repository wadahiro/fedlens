package components

import "strings"

// RequestOption is one choice of a select field, or one suggestion of a text
// field (rendered as a datalist so free input stays possible).
type RequestOption struct {
	Value string
	Label string
	// Short is how the choice is named in the "N modified" summary when the Label
	// is too long for it. Empty means the Value is used.
	Short string
	// Values are the form fields this choice fills in, by field name. They are
	// shown as the placeholders of those fields while the choice is selected, so
	// a preset's effect is visible and typing into a field is seen to override it.
	Values map[string]string
}

// RequestField is one input of the request options form. A field starts with the
// config file's value (Value). Placeholder, shown faintly, is only ever a value that
// is sent when the field is blank because fedlens or a selected profile supplies it.
type RequestField struct {
	Name        string
	Label       string
	Help        string
	Placeholder string
	// Value is what the field holds to begin with: the config file's value. The form
	// then shows the request as it will be sent, and a "modified" field is one that
	// differs from this. For a select it is the Value of the option that starts selected.
	Value string
	// Kind is "select", "text" or "textarea". Use textarea for values that are
	// long or structured, such as JSON.
	Kind    string
	Options []RequestOption
}

// RequestOptions describes the form shown next to the Login button. OIDC,
// OAuth2 and SAML each build one so the three protocols look and behave alike.
type RequestOptions struct {
	// ID names the button these options belong to ("login"). It keys the form,
	// the panel and the summary, so several buttons can each carry their own
	// options without colliding.
	ID string
	// Label is the text of that button.
	Label string
	// Style is how the button looks: "" for the primary one, "outline" for a
	// secondary one, "danger" for a destructive one such as Logout.
	Style string
	// Action is the URL the form submits to with GET.
	Action string
	// Preset is a choice that sets a base for the fields, such as a configured
	// re-authentication profile. It is shown apart from the fields: it is not one
	// of the parameters but what they are applied on top of.
	Preset *RequestField
	Fields []RequestField
	// Origin names where the fields' starting values come from, so a field typed over
	// one can say what it overrides. Empty means the config.
	Origin string
	// Note replaces the summary line shown while nothing has been changed.
	Note string
	// ExtraName names a textarea of free-form "key=value" lines for parameters
	// the form has no field for. Empty disables it.
	ExtraName string
	ExtraHelp string
}

// TriStateOptions are the choices for a boolean that may also be left unset.
// Unset is its own value because omitting an attribute is not the same request
// as sending false. unsetLabel says what leaving it unset sends (see DefaultChoice).
func TriStateOptions(unsetLabel string) []RequestOption {
	return []RequestOption{
		{Value: "", Label: unsetLabel},
		{Value: "true", Label: "true"},
		{Value: "false", Label: "false"},
	}
}

// Fallback is the faint placeholder of a text field: the value a blank field
// sends. It is empty when a blank field sends nothing, so that nothing that is not
// sent is ever shown as if it were.
func Fallback(value string) string {
	return value
}

// DefaultChoice is the label of a select's first, empty choice, saying what leaving
// it alone sends: "(form_post)", or "(not sent)" when it sends nothing.
func DefaultChoice(value string) string {
	if value == "" {
		return "(not sent)"
	}
	return "(" + value + ")"
}

// ParseKeyValueLines reads "key=value" lines, one per line. Blank lines and
// lines starting with '#' are skipped, as are lines without a key. Only the
// first '=' separates key from value, so values such as JSON or URLs survive.
func ParseKeyValueLines(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !found || key == "" {
			continue
		}
		out[key] = strings.TrimSpace(value)
	}
	return out
}

// FormID is the id of the options form for the button with the given ID. The
// button lives outside the form (in the action bar) and submits it through this
// id, so what is typed into the form is what the button sends even while the
// panel is closed.
func FormID(id string) string { return "ro-form-" + id }

// PanelID is the id of the section the button's caret expands.
func PanelID(id string) string { return "ro-panel-" + id }

// TestID builds the data-testid of one part ("btn", "toggle", "summary",
// "reset", "collapse", "card", "panel") of the options belonging to the button with the given ID.
func TestID(id, part string) string { return id + "-options-" + part }

// FieldTestID builds the data-testid of one form field.
func FieldTestID(id, name string) string { return id + "-opt-" + name }

// ButtonClass returns the classes of the button (and its caret) for the style.
func ButtonClass(style string) string {
	switch style {
	case "outline":
		return "secondary outline action-btn"
	case "danger":
		return "secondary outline action-btn action-btn-danger"
	default:
		return "action-btn"
	}
}

// DangerAttr is the value of data-danger for a style: the card takes the red edge
// while a destructive button's options are the ones shown.
func DangerAttr(style string) string {
	if style == "danger" {
		return "true"
	}
	return "false"
}

// SplitClass returns the classes of a split button's wrapper. The primary style
// is filled even when its options are closed, which the modified count needs to
// know: a count filled in the button's own colour would vanish into it.
func SplitClass(style string) string {
	if style == "" {
		return "split-btn split-filled"
	}
	return "split-btn"
}

// OriginName is the Origin with its default applied.
func (o RequestOptions) OriginName() string {
	if o.Origin == "" {
		return "config"
	}
	return o.Origin
}

// StartNote is the summary line shown while nothing has been changed.
func (o RequestOptions) StartNote() string {
	if o.Note != "" {
		return o.Note
	}
	if o.Origin == "" {
		return "Fields start with your config. A blank field sends nothing, or the faint value if there is one."
	}
	return "Fields start with the " + o.Origin + "'s values. A blank field is left out of the request."
}
