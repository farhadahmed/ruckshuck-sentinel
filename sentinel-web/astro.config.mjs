import tailwind from '@astrojs/tailwind';

export default {
  integrations: [tailwind()],
  output: 'server',
  vite: {
    ssr: {
      external: ['os', 'fs', 'path'],
    },
  },
};
