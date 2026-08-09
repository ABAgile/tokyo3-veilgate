// Package audit defines veilgated's durable flow-decision event.
package audit

import "time"

const (
	// Subject is the JetStream subject carrying veilgate decisions.
	Subject = "veilgate.audit.events"
	// StreamName is the expected JetStream stream name.
	StreamName = "veilgate_audit"
)

// Entry intentionally contains metadata only; credentials, headers, and bodies
// must never be added to the audit contract.
type Entry struct {
	Time                time.Time `json:"time"`
	FlowID              uint64    `json:"flow_id"`
	SessionID           string    `json:"session_id,omitempty"`
	Client              string    `json:"client,omitempty"`
	Method              string    `json:"method"`
	Host                string    `json:"host"`
	Port                int       `json:"port"`
	Path                string    `json:"path,omitempty"`
	Mode                string    `json:"mode"`
	DestinationIP       string    `json:"destination_ip,omitempty"`
	Decision            string    `json:"decision"`
	Reason              string    `json:"reason,omitempty"`
	Status              int       `json:"status,omitempty"`
	SecretNames         []string  `json:"secret_names,omitempty"`
	ResponseSecretNames []string  `json:"response_secret_names,omitempty"`
}
