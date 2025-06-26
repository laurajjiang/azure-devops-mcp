import { AccessToken } from "@azure/identity";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebApi } from "azure-devops-node-api";
import { z } from "zod";
import { SearchCriteria, Severity, AlertType, State } from "azure-devops-node-api/interfaces/AlertInterfaces.js";

const ADVSEC_TOOLS = {
    get_alert_by_id: "advsec_get_alert_by_id",
    list_alerts_by_repo: "advsec_list_alerts_by_repo",
    get_enablement_status_by_repo: "advsec_get_enablement_status_by_repo",
    update_enablement_status_by_repo: "advsec_update_enablement_status_by_repo",
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
      alertType: z.enum(["secrets", "dependencies", "code"]).optional().describe("Optional alert type to filter alerts. Defaults to all alerts."),
      severities: z.array(z.enum(["low", "medium", "high", "critical"])).optional().describe("Array of severity levels to filter alerts. Defaults to ['critical', 'high']."),
      state: z.enum(["active", "dismissed", "fixed"]).optional().describe("Optional state to filter alerts. Defaults to 'active'."),
      continuationToken: z.string().optional().describe("Token to continue fetching alerts from a previous request."),
    },
    async ({
      project,
      repositoryId,
      alertType,
      severities = ["critical", "high"],
      state = "active",
      continuationToken,
    }) => {
        const connection = await connectionProvider();
        const alertApi = await connection.getAlertApi();
        
        const severityMap: { [key: string]: Severity } = {
          "low": Severity.Low,
          "medium": Severity.Medium, 
          "high": Severity.High,
          "critical": Severity.Critical
        };
    
        const stateMap: { [key: string]: State } = {
          "active": State.Active,
          "dismissed": State.Dismissed,
          "fixed": State.Fixed
        };
        
        const alertTypeMap: { [key: string]: AlertType } = {
          "secrets": AlertType.Secret,
          "dependencies": AlertType.Dependency,
          "code": AlertType.Code
        };
        
        const searchCriteriaObj: SearchCriteria = {
          states: [stateMap[state]],
          severities: severities.map(s => severityMap[s]),
          ...(alertType && { alertType: alertTypeMap[alertType] })
        };
        
        const alerts = await alertApi.getAlerts(
          project, 
          repositoryId, 
          50, 
          "severity", 
          searchCriteriaObj,
          undefined, // expand option
          continuationToken
        );

        return {
          content: [{ type: "text", text: JSON.stringify(alerts, null, 2) }],
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
        const alert = await managementApi.getRepoEnablementStatus2(project, repositoryId, true);

        return {
          content: [{ type: "text", text: JSON.stringify(alert, null, 2) }],
        };
      
    }
  );
  
  server.tool(
    ADVSEC_TOOLS.update_enablement_status_by_repo,
    "Update the Advanced Security enablement properties for a particular repository.",
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
        //const alert = await managementApi.updateRepoAdvSecEnablementStatus2(project, repositoryId, true);

        return {
          content: [{ type: "text", text: JSON.stringify(alert, null, 2) }],
        };
      
    }
  );
  
}

export { ADVSEC_TOOLS, configureAdvSecTools };