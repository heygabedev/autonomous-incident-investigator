import { render, screen } from "@testing-library/react";

import { App } from "./App";

test("renders the product name and foundation status", () => {
  render(<App />);

  expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
    "Autonomous Incident Investigator",
  );
  expect(screen.getByLabelText("Pairing code from the app terminal")).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: "Foundation ready" })).not.toBeInTheDocument();
});
