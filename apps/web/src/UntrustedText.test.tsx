import { render, screen } from "@testing-library/react";
import { UntrustedText } from "./UntrustedText";

test("keeps report markup, scripts and remote content inert", () => {
  const text = '<img src="https://example.invalid/private" onerror="alert(1)">' +
    '<script>alert(2)</script>[open](javascript:alert(3))';
  const { container } = render(<UntrustedText text={text} />);
  expect(screen.getByText(text)).toBeInTheDocument();
  expect(container.querySelectorAll("img, script, a, iframe")).toHaveLength(0);
});
