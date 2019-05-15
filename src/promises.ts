import pLimit, { Limit } from 'p-limit'
import bluebird from './bluebird'

class IgnoreError extends Error {
  public constructor() {
    super()
    this.name = 'IgnoreError'
  }
}

type promiseLike = () => {} | PromiseLike<{}>
const rejectOnFalsey = (limit: Limit) => async (promise: promiseLike) => {
  const returnVal = await limit(promise)
  if (returnVal) return returnVal
  return Promise.reject(new IgnoreError())
}

// take an array of promises
// run n (`concurrency`) promises concurrently
// when any promise is fulfilled with a truthy value, stop
async function waitUntilFirstTruthyPromise(promises: promiseLike[], { concurrency = 16 } = {}) {
  const limit = pLimit(concurrency)
  await bluebird.any(promises.map(rejectOnFalsey(limit))).catch(bluebird.AggregateError, (err) => {
    if (!(err[0] instanceof IgnoreError)) throw err[0]
  })
}

export default waitUntilFirstTruthyPromise
