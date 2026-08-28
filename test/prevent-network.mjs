globalThis.fetch = async () => {
  throw new Error('test failure: offline verification attempted network access')
}
