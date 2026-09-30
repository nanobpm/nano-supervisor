//! Tiny BPMN generator: one process with a single service task, so an engine
//! test can deploy a fresh process with a unique job type and create an instance
//! carrying whatever variables the test needs. Mirrors `spike/spike.bpmn`.

/// A one-task process definition `process_id` whose service task has
/// `jobType = job_type`. Deploy it, then create an instance to enqueue one job.
pub fn single_task(process_id: &str, job_type: &str) -> String {
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
      </bpmn:extensionElements>
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
}
