import { render, screen } from "@testing-library/react";

import { App } from "./App";

test("requires pairing before showing investigations", () => {
  render(<App />);

  expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
    "Autonomous Incident Investigator",
  );
  expect(screen.getByLabelText("Pairing code from the app terminal")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Start investigation" })).not.toBeInTheDocument();
});
