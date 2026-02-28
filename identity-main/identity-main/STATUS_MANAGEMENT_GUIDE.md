# Identity Management System - Edit Page Enhancements

## Status Management Features Added

### 1. **Visual Status Indicators**
The edit page now displays the current status with color-coded badges:
- **Pending**: Yellow badge with alert styling
- **Active**: Green badge with success styling  
- **Suspended**: Red badge with warning styling
- **Inactive**: Gray badge with neutral styling
- **Archived**: Blue badge with info styling

### 2. **Enhanced Status Change Interface**
A new "Identity Status Management" card section includes:
- Current status display prominently at the top
- A dedicated dropdown to select new status
- Only available transitions are shown (based on workflow rules)
- Icons and descriptive text for each status option

### 3. **Status Workflow Information**
A helpful alert box displays the complete status lifecycle:
```
Pending → Active → (Suspended ↔ Active) → Inactive → Archived
```

With descriptions for each status:
- **Pending**: New identity, waiting for activation
- **Active**: Identity is active and in use
- **Suspended**: Temporarily suspended, can be restored to Active
- **Inactive**: No longer active, eligible for archival after 5 years
- **Archived**: Final status, no changes possible

### 4. **Smart Status Transitions**
The system enforces valid transitions:
- **From Pending**: Can only go to Active
- **From Active**: Can go to Suspended or Inactive
- **From Suspended**: Can go back to Active or to Inactive
- **From Inactive**: Can only go to Archived (after 5 years)
- **From Archived**: No transitions (read-only)

### 5. **Confirmation on Status Change**
When submitting the form with a status change, users are asked to confirm the transition before saving.

### 6. **Access Control**
- Archived identities cannot be edited
- Status dropdown is disabled for archived records
- Submit button is disabled for archived records

### 7. **Additional Navigation**
Quick links added to the edit page:
- View Identity (see full details)
- All Identities (view list)
- Home (return to home page)

### 8. **Date Tracking for 5-Year Rule**
For Inactive status, the system tracks:
- When the status was changed to Inactive
- Remaining time before archival is allowed
- This is displayed when viewing an Inactive identity

## Status Workflow Implementation

The system follows a proper state machine pattern:
1. **Pending** → Awaiting activation
2. **Active** → Ready for use
3. **Suspended** → Temporarily unavailable (can be restored)
4. **Inactive** → Permanently unavailable (after 5 years can be archived)
5. **Archived** → Final, immutable state

This ensures data integrity and proper identity lifecycle management.
