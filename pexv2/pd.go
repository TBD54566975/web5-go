package pexv2

// PresentationDefinition represents a DIF Presentation Definition defined [here].
// Presentation Definitions are objects that articulate what proofs a Verifier requires
//
// [here]: https://identity.foundation/presentation-exchange/#presentation-definition
type PresentationDefinition struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	Purpose          string            `json:"purpose,omitempty"`
	InputDescriptors []InputDescriptor `json:"input_descriptors"`
}

// InputDescriptor represents a DIF Input Descriptor defined [here].
// Input Descriptors are used to describe the information a Verifier requires of a Holder.
//
// [here]: https://identity.foundation/presentation-exchange/#input-descriptor
type InputDescriptor struct {
	ID          string      `json:"id"`
	Name        string      `json:"name,omitempty"`
	Purpose     string      `json:"purpose,omitempty"`
	Constraints Constraints `json:"constraints"`
}

// Constraints contains the requirements for a given Input Descriptor.
type Constraints struct {
	Fields []Field `json:"fields,omitempty"`
}

// Field contains the requirements for a given field within a proof
type Field struct {
	ID        string       `json:"id,omitempty"`
	Name      string       `json:"name,omitempty"`
	Path      []string     `json:"path,omitempty"`
	Purpose   string       `json:"purpose,omitempty"`
	Filter    *Filter      `json:"filter,omitempty"`
	Optional  bool         `json:"optional,omitempty"`
	Predicate *Optionality `json:"predicate,omitempty"`
}

// Optionality is a type alias for the possible values of the predicate field
type Optionality string

// Constants for Optionality values
const (
	Required  Optionality = "required"
	Preferred Optionality = "preferred"
)

// Filter is a JSON Schema that is applied against the value of a field.
type Filter struct {
	Type     string  `json:"type,omitempty"`
	Pattern  string  `json:"pattern,omitempty"`
	Const    string  `json:"const,omitempty"`
	Contains *Filter `json:"contains,omitempty"`
}
