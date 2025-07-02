import { AccessToken } from "@azure/identity";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebApi } from "azure-devops-node-api";
import { z } from "zod";
import { SearchCriteria, Severity, AlertType, State } from "azure-devops-node-api/interfaces/AlertInterfaces.js";
import { AdvSecEnablementStatusUpdate } from "azure-devops-node-api/interfaces/ManagementInterfaces.js";

const ADVSEC_TOOLS = {
    get_alert_by_id: "advsec_get_alert_by_id",
    list_alerts_by_repo: "advsec_list_alerts_by_repo",
    get_enablement_status_by_repo: "advsec_get_enablement_status_by_repo",
    update_enablement_status_by_repo: "advsec_update_enablement_status_by_repo",
}

function getAlertSeverityName(alertSeverity: Severity): string {
    return Severity[alertSeverity].toLowerCase();
}

function getAlertTypeName(alertType: AlertType): string {
    return AlertType[alertType].toLowerCase();
}

function getAlertStateName(alertState: State): string {
    return State[alertState].toLowerCase();
}

function configureAdvSecTools(
  server: McpServer,
  tokenProvider: () => Promise<AccessToken>,
  connectionProvider: () => Promise<WebApi>
) {
  
  server.tool(
    ADVSEC_TOOLS.get_alert_by_id,
    "Get an Advanced Security alert by ID.",
    {
      project: z.string().describe("Project ID or name to get the alert from"),
      repositoryId: z.string().describe("The ID of the repository where the alert is located."),
      alertId: z.number().describe("The ID of the alert to retrieve."),
      ref: z.string().optional().describe("Optional ref (branch) to get the alert from"),
      expand: z.enum(["None", "ValidationFingerprint"]).optional().describe("Expand alert attributes. Possible options are ValidationFingerprint or None")
    },
    async ({
      project,
      alertId,
      repositoryId,
      ref,
      expand,
    }) => {
        const connection = await connectionProvider();
        const alertApi = await connection.getAlertApi();
        const alert = await alertApi.getAlert(project, alertId, repositoryId, ref, expand as any);

        return {
          content: [{ type: "text", text: JSON.stringify(alert, null, 2) }],
        };
      
    }
  ); 

  server.tool(
    ADVSEC_TOOLS.list_alerts_by_repo,
    "Get a list of Advanced Security alerts by repository.",
    {
      project: z.string().describe("Project ID or name to get the alert from"),
      repositoryId: z.string().describe("The ID of the repository where the alert is located."),
      top: z.number().default(100).describe("The maximum number of alerts to return. Defaults to 100."),
      searchCriteria: z.object({
        type: z.nativeEnum(AlertType).optional().describe("Filter by alert type"),
        state: z.nativeEnum(State).default(State.Active).describe("Filter by alert state")},
      ).optional().describe("Search criteria to filter alerts. Can include type, severity, state, etc."),
      continuationToken: z.string().optional().describe("Token to continue fetching alerts from a previous request."),
    },
    async ({
      project,
      repositoryId,
      top,
      searchCriteria,
      continuationToken,
    }) => {
        const connection = await connectionProvider();
        const alertApi = await connection.getAlertApi();
        const alerts = await alertApi.getAlerts(
          project, 
          repositoryId, 
          top,
          "severity", // orderBy
          searchCriteria as SearchCriteria, // Convert to SearchCriteria type,
          undefined,
          continuationToken
        );

        const arrayAlerts = Object.values(alerts)
        const filteredAlerts = arrayAlerts?.map((alert) => {
            // Helper function to safely extract rule information
            const getFirstRule = () => {
                return alert.tools?.[0]?.rules?.[0];
            };
            
            const firstRule = getFirstRule();
            
            return {
                id: alert.alertId,
                type: alert.alertType ? getAlertTypeName(alert.alertType) : 'Unknown',
                severity: alert.severity ? getAlertSeverityName(alert.severity) : 'Unknown',
                state: alert.state ? getAlertStateName(alert.state) : 'Unknown',
                title: alert.title,
                lastSeenDate: alert.lastSeenDate,
                firstSeenDate: alert.firstSeenDate,
                introducedDate: alert.introducedDate,
                toolName: alert.tools?.[0]?.name || 'Unknown tool',
                ruleName: firstRule?.friendlyName || 'Unknown rule',
                description: firstRule?.description || 'No description available',
                remediation: firstRule?.helpMessage || 'No remediation information available'
            };
        });

        return {
          content: [{ type: "text", text: JSON.stringify(filteredAlerts, null, 2) }],
        };
      
      
    }
  );
  
  server.tool(
    ADVSEC_TOOLS.get_enablement_status_by_repo,
    "Get the enablement status of Advanced Security for a repository.",
    {
      project: z.string().describe("Project ID or name to get the alert from"),
      repositoryId: z.string().describe("The ID of the repository where the alert is located."),
    },
    async ({
      project,
      repositoryId,
    }) => {
        const connection = await connectionProvider();
        const managementApi = await connection.getManagementApi();
        const enablement = await managementApi.getRepoEnablementStatus(project, repositoryId, true);

        return {
          content: [{ type: "text", text: JSON.stringify(enablement, null, 2) }],
        };
      
    }
  );
  
  server.tool(
    ADVSEC_TOOLS.update_enablement_status_by_repo,
    "Update the Advanced Security enablement properties for a particular repository.",
    {
      project: z.string().describe("Project ID or name to update enablement for"),
      repositoryId: z.string().describe("The ID of the repository to update enablement for"),
      enablementProperties: z.object({
        advSecEnabled: z.boolean().describe("Whether Advanced Security is enabled for the repository"),
        blockPushes: z.boolean().optional().describe("Whether to block pushes when security issues are detected"),
        dependabotEnabled: z.boolean().optional().describe("Whether Dependabot is enabled for dependency updates"),
        dependencyScanningInjectionEnabled: z.boolean().optional().describe("Whether dependency scanning injection is enabled"),
        codeQLEnabled: z.boolean().optional().describe("Whether CodeQL default setup is enabled")
      }).describe("The Advanced Security enablement properties to update Advanced Security with.")
    },
    async ({
      project,
      repositoryId,
      enablementProperties
    }) => {
        const connection = await connectionProvider();
        const managementApi = await connection.getManagementApi();
        
        // Call the update method with the enablement properties object
        const result = await managementApi.updateRepoAdvSecEnablementStatus(enablementProperties as AdvSecEnablementStatusUpdate, project, repositoryId);

        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      
    }
  );
  
}

export { ADVSEC_TOOLS, configureAdvSecTools };