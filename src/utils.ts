export const collapsibleWrapper = (title: string, content: string) => {
  return `
<details>
<summary>${title}</summary>

${content}

</details>
`;
};
