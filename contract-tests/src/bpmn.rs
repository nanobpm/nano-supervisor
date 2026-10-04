//! Tiny BPMN generator: one process with a single service task, so an engine
//! test can deploy a fresh process with a unique job type and create an instance
//! carrying whatever variables the test needs. Mirrors `spike/spike.bpmn`.
//! The task carries the canonical external-agent marker
//! (`<zeebe:agentDefinition agentType="external"/>`), as every production agent task does:
//! the Node worker opens an AgentInstance for it, and without it takes an error path.

/// A one-task process definition `process_id` whose service task has
/// `jobType = job_type`. Deploy it, then create an instance to enqueue one job.
pub fn single_task(process_id: &str, job_type: &str) -> String {
    single_task_with_headers(process_id, job_type, &[])
}

/// [`single_task`] plus static task headers (`<zeebe:taskHeaders>`), e.g. a
/// `linkedResources` declaration the engine resolves at activation.
pub fn single_task_with_headers(
    process_id: &str,
    job_type: &str,
    custom_headers: &[(&str, &str)],
) -> String {
    let headers_xml = if custom_headers.is_empty() {
        String::new()
    } else {
        let mut h = String::from("        <zeebe:taskHeaders>\n");
        for (k, v) in custom_headers {
            h.push_str(&format!(
                "          <zeebe:header key=\"{}\" value=\"{}\"/>\n",
                xml_escape(k),
                xml_escape(v)
            ));
        }
        h.push_str("        </zeebe:taskHeaders>\n");
        h
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL"
                  xmlns:zeebe="http://camunda.org/schema/zeebe/1.0"
                  id="defs-{process_id}"
                  targetNamespace="http://bpmn.io/schema/bpmn">
  <bpmn:process id="{process_id}" isExecutable="true">
    <bpmn:startEvent id="start"><bpmn:outgoing>f1</bpmn:outgoing></bpmn:startEvent>
    <bpmn:sequenceFlow id="f1" sourceRef="start" targetRef="task"/>
    <bpmn:serviceTask id="task" name="work">
      <bpmn:extensionElements>
        <zeebe:taskDefinition type="{job_type}"/>
        <zeebe:agentDefinition agentType="external"/>
{headers_xml}      </bpmn:extensionElements>
      <bpmn:incoming>f1</bpmn:incoming>
      <bpmn:outgoing>f2</bpmn:outgoing>
    </bpmn:serviceTask>
    <bpmn:sequenceFlow id="f2" sourceRef="task" targetRef="end"/>
    <bpmn:endEvent id="end"><bpmn:incoming>f2</bpmn:incoming></bpmn:endEvent>
  </bpmn:process>
</bpmn:definitions>
"#
    )
}

/// The five XML predefined entities, so a header value can carry JSON quotes
/// and `&` without breaking the document.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embeds_process_id_and_job_type() {
        let xml = single_task("ct-proc-1", "ct-job-1");
        assert!(xml.contains(r#"id="ct-proc-1""#));
        assert!(xml.contains(r#"type="ct-job-1""#));
        assert!(xml.contains("bpmn:serviceTask"));
    }

    #[test]
    fn task_headers_are_embedded_and_escaped() {
        let xml = single_task_with_headers(
            "ct-proc-2",
            "ct-job-2",
            &[(
                "linkedResources",
                r#"[{"resourceKey":"5","linkName":"prompt"}]"#,
            )],
        );
        assert!(xml.contains("<zeebe:taskHeaders>"));
        assert!(xml.contains(r#"key="linkedResources""#));
        // JSON quotes inside the value are XML-escaped.
        assert!(xml.contains("&quot;resourceKey&quot;"));
        // No headers requested → no taskHeaders block at all.
        assert!(!single_task("ct-proc-3", "ct-job-3").contains("taskHeaders"));
    }
}
