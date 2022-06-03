import * as core from "@actions/core";
import { PullReportResponse, Finding } from "./types/platform";
import { SummaryTableRow } from "@actions/core/lib/summary";

export type SummaryType = "short" | "long" | string;
export async function githubJobSummary(which: SummaryType, testResults: Promise<PullReportResponse>) {
  switch (which) {
    case "short":
      return githubJobSummaryShort(testResults);
    case "long":
      return githubJobSummaryLong(testResults)
  }
}

export async function githubJobSummaryLong(
  getTestResults: Promise<PullReportResponse>
) {
  const report = await getTestResults;

  const findingsTable = getFindingsTable(report);
  const dependenciesTable = getDependenciesTable(report);

  return core.summary
    .addImage("https://www.nowsecure.com/wp-content/uploads/2022/03/Logo-Nowsecure.png", "NowSecure Logo")
    .addHeading(":rocket: Security Test Results :rocket:")
    .addTable(findingsTable)
    .addSeparator()
    .addHeading(":robot: Dependencies :robot:")
    .addTable(dependenciesTable)
    .addLink("View NowSecure Report", "https://lab.nowsecure.com");
}

export async function githubJobSummaryShort(
  testResults: Promise<PullReportResponse>
) {
  const report = await testResults;
  const assessmentIndex = 0;
  const firstAssessment = report.data.auto.assessments[assessmentIndex];

  type Grouping = { pass: Finding[], fail: Finding[] };
  const grouping: Grouping = { pass: [], fail: [] };
  const findingsGroupedBy = firstAssessment.report.findings.reduce<Grouping>((acc, finding) => {
    const { check, affected } = finding;
    if (affected && check.issue?.cvss > 0) {
      acc.fail.push(finding);
    } else {
      acc.pass.push(finding);
    }
    return acc;
  }, grouping);

  const testResultHeader = [
    { data: 'Test Result', header: true }, { data: 'Count', header: true }
  ]

  const results = [
    [":white_check_mark: Pass", findingsGroupedBy.pass.length.toString()],
    [":red_circle: Fail", findingsGroupedBy.fail.length.toString()],
    [":robot: Dependencies", firstAssessment.deputy.components.length.toString()]
  ];

  const formatDetail = (findings: Finding[]) => findings.map(({ key, title}) => `- ${key} - ${title}`).join("<br>");

  return core.summary
    .addImage("https://www.nowsecure.com/wp-content/uploads/2022/03/Logo-Nowsecure.png", "NowSecure Logo")
    .addHeading(":rocket: Security Test Results :rocket:")
    .addTable([testResultHeader, ...results])
    .addDetails("Risks", formatDetail(findingsGroupedBy.fail))
    .addSeparator()
    .addLink("View NowSecure Report", "https://lab.nowsecure.com");
}

export async function githubWriteJobSummary(): Promise<void> {
  if (process.env.GITHUB_STEP_SUMMARY) {
    await core.summary.write();
  }
}

export function getDependenciesTable(report: PullReportResponse): SummaryTableRow[] {
  const header: SummaryTableRow = [
    { data: 'Dependency', header: true }, { data: 'Version', header: true }, { data: 'File', header: true }
  ];
  const assessmentIndex = 0;
  const firstAssessment = report.data.auto.assessments[assessmentIndex];
  const deps = firstAssessment.deputy.components
    .filter(({version}) => version)
    .map<SummaryTableRow>(({ source: file, name, version }) => {
      return [name ?? "name", version ?? "version", file ?? "file"];
    });
  return [header, ...deps];
}

export function getFindingsTable(report: PullReportResponse): SummaryTableRow[] {
  const header: SummaryTableRow = [
    { data: 'Checks', header: true }, { data: 'Pass', header: true }, { data: 'Category', header: true }, { data: 'Summary', header: true}
  ];
  const assessmentIndex = 0;
  const firstAssessment = report.data.auto.assessments[assessmentIndex];
  const checks = firstAssessment.report.findings
    .filter(({ affected, check }) => affected && check.issue?.cvss > 0)
    .map<SummaryTableRow>(({ check, key, affected }) => {
      const mark = affected ? ":red_circle:" : ":white_check_mark:";
      const category = check.issue?.category ?? "misc";
      const title = check.issue?.title ?? "See report for details";
      return [key, mark, category, title];
    });
  return [header, ...checks];
}
