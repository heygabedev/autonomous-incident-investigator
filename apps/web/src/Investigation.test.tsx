import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { ReportView } from "./Investigation";
import { ev, report } from "./test/factories";

test("renders untrusted recommendation strings as inert text", () => {
  const payload = '<img src="https://attacker.example/pixel" onerror="alert(1)">';
  const { container } = render(<ReportView report={{ ...report, recommendations: [{
    cause: "missing_required_environment_variable", instruction: payload, prerequisites: payload,
    risk: "risk", rollback: "rollback", validation: "verify", evidence_ids: [ev],
    source: "reviewed_template", execution: "operator_only",
  }] }} />);
  expect(screen.getByRole("heading", { name: payload })).toBeInTheDocument();
  expect(container.querySelector("img")).toBeNull();
  expect(container.querySelector("script")).toBeNull();
  expect(screen.queryByRole("button", { name: /execute/i })).not.toBeInTheDocument();
  expect(screen.getAllByRole("link")[0]).toHaveAttribute("href", `#${ev}`);
});

test("unresolved reports do not invent recommendations or probabilities", () => {
  render(<ReportView report={{ ...report, status: "unresolved", hypotheses: [], recommendations: [] }} />);
  expect(screen.getByText("No action is recommended with the current evidence.")).toBeInTheDocument();
  expect(screen.getByText(/uncalibrated/)).toBeInTheDocument();
});
