# sv

Everything you need to build a Svelte project, powered by [`sv`](https://github.com/sveltejs/cli).

## Creating a project

If you're seeing this, you've probably already done this step. Congrats!

```sh
# create a new project
npx sv create my-app
```

To recreate this project with the same configuration:

```sh
# recreate this project
npx sv create --template minimal --types ts --install npm dashboard
```

## Developing

Once you've created a project and installed dependencies with `npm install` (or `pnpm install` or `yarn`), start a development server:

```sh
npm run dev

# or start the server and open the app in a new browser tab
npm run dev -- --open
```

## Building

To create a production version of your app:

```sh
npm run build
```

You can preview the production build with `npm run preview`.

> To deploy your app, you may need to install an [adapter](https://svelte.dev/docs/kit/adapters) for your target environment.

## API Client Usage

### Updating Rules

Use `updateRule()` to modify any rule property, including enabled state:

```typescript
import { api } from '$lib/api';

// Disable a rule
await api.updateRule('rule-942100', { enabled: false });

// Enable a rule
await api.updateRule('rule-942100', { enabled: true });

// Update multiple properties
await api.updateRule('rule-942100', {
  enabled: true,
  severity: 'HIGH',
  tags: ['sqli', 'critical']
});
```

> **Breaking Change (v1.1)**: The deprecated `toggleRule()` method has been removed. Use `updateRule()` instead.

