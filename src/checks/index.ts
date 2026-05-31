import type { Check } from '../types'
import { accessChecks } from './access'
import { routeChecks } from './routes'
import { configChecks } from './config'

export const ALL_CHECKS: Check[] = [...accessChecks, ...routeChecks, ...configChecks]
