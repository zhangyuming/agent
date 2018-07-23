package agent

import (
	"net/http"

	"bitbucket.org/portainer/agent"
	httperror "bitbucket.org/portainer/agent/http/error"
	"github.com/gorilla/mux"
)

const (
	errAgentManagementDisabled = agent.Error("Agent management is disabled")
)

// Handler is the HTTP handler used to handle agent operations.
type Handler struct {
	*mux.Router
	clusterService agent.ClusterService
}

// NewHandler returns a pointer to an Handler
// It sets the associated handle functions for all the agent related HTTP endpoints.
func NewHandler(cs agent.ClusterService) *Handler {
	h := &Handler{
		Router:         mux.NewRouter(),
		clusterService: cs,
	}

	h.Handle("/agents",
		httperror.LoggerHandler(h.agentList)).Methods(http.MethodGet)

	return h
}
