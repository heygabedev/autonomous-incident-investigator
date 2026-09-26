import { render, screen } from "@testing-library/react";

import { App } from "./App";

test("renders the product name and foundation status", () => {
  render(<App />);

  expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
    "Autonomous Incident Investigator",
  );
  expect(screen.getByRole("heading", { name: "Foundation ready" })).toBeInTheDocument();
});
