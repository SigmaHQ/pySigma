from sigma.processing.pipelines.crowdstrike import crowdstrike_splunk_pipeline
from sigma.processing.pipelines.sysmon import sysmon_pipeline
from sigma.processing.resolver import ProcessingPipelineResolver

DefaultPipelineResolver = ProcessingPipelineResolver({
    "sysmon": sysmon_pipeline,
    "crowdstrike": crowdstrike_splunk_pipeline,
})