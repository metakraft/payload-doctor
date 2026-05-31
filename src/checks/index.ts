import type { Check } from '../types'
import { accessChecks } from './access'
import { routeChecks } from './routes'
import { configChecks } from './config'
import { renderingChecks } from './rendering'
import { qualityChecks } from './quality'

export const ALL_CHECKS: Check[] = [
  ...accessChecks,
  ...routeChecks,
  ...configChecks,
  ...renderingChecks,
  ...qualityChecks,
]
