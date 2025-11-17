// See LICENSE for license details.

#include "processor.h"
#include "mmu.h"
#include "disasm.h"
#include <cassert>

bool is_main = false; // determine whether instructions are in main or not
bool is_trap = false; // determine whether instructions are in trap handler or not
uint64_t cycle_num = 0; // variable for counting cycle numbers
reg_t trap_addr; // address of ins when trap is taken
reg_t branch_addr; // address of ins when branch is taken

const char *MEM_R[] = {"lb", "lh", "lw", "ld", "lbu", "lhu", "lwu"}; // instructions which read memory

struct insn_t *IFIDinsn = NULL; //instruction located in IF/ID pipeline register
struct insn_t *IDEXinsn = NULL; //instruction located in ID/EX pipeline register
struct insn_t *EXMEMinsn = NULL; //instruction located in EX/MEM pipeline register
struct insn_t *MEMWBinsn = NULL; //instruction located in MEM/WB pipeline register

// functions which decodes instruction

inline const char* decode_R(uint64_t funct3, uint64_t funct7) { // decode R type instructions
    switch (funct3) {
        case 0x00: return (funct7 == 0x00 ? "add" : "sub");
        case 0x07: return "and";
        case 0x06: return "or";
        case 0x04: return "xor";
        case 0x01: return "sll";
        case 0x05: return (funct7 == 0x00 ? "srl" : "sra");
        case 0x02: return "slt";
        case 0x03: return "sltu";
        default:   return "unknown";
    }
}

inline const char* decode_i(uint64_t funct3, uint64_t funct7) { // decode i type instructions(32 bit imm)
    switch (funct3) {
        case 0x00: return "addi";
        case 0x07: return "andi";
        case 0x06: return "ori";
        case 0x04: return "xori";
        case 0x01: return "slli";
        case 0x05: return (funct7 == 0x00 ? "srli" : "srai");
        case 0x02: return "slti";
        case 0x03: return "sltiu";
        default:   return "unknown";
    }
}

inline const char* decode_I(uint64_t funct3) { // decode I type instructions(load)
    switch (funct3) {
        case 0x00: return "lb";
        case 0x01: return "lh";
        case 0x02: return "lw";
        case 0x03: return "ld";
        case 0x04: return "lbu";
        case 0x05: return "lhu";
        case 0x06: return "lwu";
        default:   return "unknown";
    }
}

inline const char* decode_S(uint64_t funct3) { // decode S type inst(store)
    switch (funct3) {
        case 0x00: return "sb";
        case 0x01: return "sh";
        case 0x02: return "sw";
        case 0x03: return "sd";
        default:   return "unknown";
    }
}

inline const char* decode_B(uint64_t funct3) { // decode B type (branch)
    switch (funct3) {
        case 0x00: return "beq";
        case 0x01: return "bne";
        case 0x04: return "blt";
        case 0x05: return "bge";
        case 0x06: return "bltu";
        case 0x07: return "bgeu";
        default:   return "unknown";
    }
}

inline const char* decode_F(uint64_t funct3) { // decode F type (fence)
    return (funct3 == 0x00 ? "fence" : "fence.i");
} 

inline const char* decode_E(uint64_t funct3, int64_t imm) { //decode E type (system)
    switch (funct3) {
        case 0x00: return (imm == 0x0 ? "ecall" : "ebreak");
        case 0x01: return "csrrw";
        case 0x02: return "csrrs";
        case 0x03: return "csrrc";
        case 0x05: return "csrrwi";
        case 0x06: return "csrrsi";
        case 0x07: return "csrrci";
        default:   return "unknown";
    }
}

inline const char* decode_w(uint64_t funct3, uint64_t funct7) { // decode w type (32bit imm)
    switch (funct3) {
        case 0x00: return "addiw";
        case 0x01: return "slliw";
        case 0x05: return (funct7 == 0x00 ? "srliw" : "sraiw");
        default:   return "unknown";
    }
}

inline const char* decode_W(uint64_t funct3, uint64_t funct7) { // decode W type (32bit reg)
    switch (funct3) {
        case 0x00: return (funct7 == 0x00 ? "addw" : "subw");
        case 0x01: return "sllw";
        case 0x05: return (funct7 == 0x00 ? "srlw" : "sraw");
        default:   return "unknown";
    }
}

// main function for decoding instructions
inline const char* decode_inst(insn_t &insn) {
    uint64_t opcode = insn.opcode();
    uint64_t funct3 = insn.funct3();
    uint64_t funct7 = insn.funct7();

    switch (opcode) {
        case 0x33: // R-type
            return decode_R(funct3, funct7);
        case 0x73: // E-type (system)
            return decode_E(funct3, insn.i_imm());
        case 0x13: // i-type (arith imm)
            return decode_i(funct3, funct7);
        case 0x1b: // w-type (32bit imm)
            return decode_w(funct3, funct7);
        case 0x3b: // W-type (32bit reg)
            return decode_W(funct3, funct7);
        case 0x03: // I-type (load)
            return decode_I(funct3);
        case 0x23: // S-type (store)
            return decode_S(funct3);
        case 0x63: // B-type (branch)
            return decode_B(funct3);
        case 0x6f:
            return "jal";
        case 0x67:
            return "jalr";
        case 0x17:
            return "auipc";
        case 0x37:
            return "lui";
        case 0x0f: // F-type (fence)
            return decode_F(funct3);
        default:
            return "unknown";
    }
}

// check if instruction reads memory
inline bool is_mem_r(insn_t &insn){
  const char *name = decode_inst(insn);
  for(auto s : MEM_R){
    if(!strcmp(name,s)) return true;
  }

  return false;
}

#ifdef RISCV_ENABLE_COMMITLOG
static void commit_log_reset(processor_t* p)
{
  p->get_state()->log_reg_write.clear();
  p->get_state()->log_mem_read.clear();
  p->get_state()->log_mem_write.clear();
}

static void commit_log_stash_privilege(processor_t* p)
{
  state_t* state = p->get_state();
  state->last_inst_priv = state->prv;
  state->last_inst_xlen = p->get_xlen();
  state->last_inst_flen = p->get_flen();
}

static void commit_log_print_value(FILE *log_file, int width, const void *data)
{
  assert(log_file);

  switch (width) {
    case 8:
      fprintf(log_file, "0x%01" PRIx8, *(const uint8_t *)data);
      break;
    case 16:
      fprintf(log_file, "0x%04" PRIx16, *(const uint16_t *)data);
      break;
    case 32:
      fprintf(log_file, "0x%08" PRIx32, *(const uint32_t *)data);
      break;
    case 64:
      fprintf(log_file, "0x%016" PRIx64, *(const uint64_t *)data);
      break;
    default:
      // max lengh of vector
      if (((width - 1) & width) == 0) {
        const uint64_t *arr = (const uint64_t *)data;

        fprintf(log_file, "0x");
        for (int idx = width / 64 - 1; idx >= 0; --idx) {
          fprintf(log_file, "%016" PRIx64, arr[idx]);
        }
      } else {
        abort();
      }
      break;
  }
}

static void commit_log_print_value(FILE *log_file, int width, uint64_t val)
{
  commit_log_print_value(log_file, width, &val);
}

const char* processor_t::get_symbol(uint64_t addr)
{
  return sim->get_symbol(addr);
}

static void commit_log_print_insn(processor_t *p, reg_t pc, insn_t insn)
{
  FILE *log_file = p->get_log_file();

  auto& reg = p->get_state()->log_reg_write;
  auto& load = p->get_state()->log_mem_read;
  auto& store = p->get_state()->log_mem_write;
  int priv = p->get_state()->last_inst_priv;
  int xlen = p->get_state()->last_inst_xlen;
  int flen = p->get_state()->last_inst_flen;

  // print core id on all lines so it is easy to grep
  fprintf(log_file, "core%4" PRId32 ": ", p->get_id());

  fprintf(log_file, "%1d ", priv);
  commit_log_print_value(log_file, xlen, pc);
  fprintf(log_file, " (");
  commit_log_print_value(log_file, insn.length() * 8, insn.bits());
  fprintf(log_file, ")");
  bool show_vec = false;

  for (auto item : reg) {
    if (item.first == 0)
      continue;

    char prefix;
    int size;
    int rd = item.first >> 4;
    bool is_vec = false;
    bool is_vreg = false;
    switch (item.first & 0xf) {
    case 0:
      size = xlen;
      prefix = 'x';
      break;
    case 1:
      size = flen;
      prefix = 'f';
      break;
    case 2:
      size = p->VU.VLEN;
      prefix = 'v';
      is_vreg = true;
      break;
    case 3:
      is_vec = true;
      break;
    case 4:
      size = xlen;
      prefix = 'c';
      break;
    default:
      assert("can't been here" && 0);
      break;
    }

    if (!show_vec && (is_vreg || is_vec)) {
        fprintf(log_file, " e%ld %s%ld l%ld",
                p->VU.vsew,
                p->VU.vflmul < 1 ? "mf" : "m",
                p->VU.vflmul < 1 ? (reg_t)(1 / p->VU.vflmul) : (reg_t)p->VU.vflmul,
                p->VU.vl->read());
        show_vec = true;
    }

    if (!is_vec) {
      if (prefix == 'c')
        fprintf(log_file, " c%d_%s ", rd, csr_name(rd));
      else
        fprintf(log_file, " %c%2d ", prefix, rd);
      if (is_vreg)
        commit_log_print_value(log_file, size, &p->VU.elt<uint8_t>(rd, 0));
      else
        commit_log_print_value(log_file, size, item.second.v);
    }
  }

  for (auto item : load) {
    fprintf(log_file, " mem ");
    commit_log_print_value(log_file, xlen, std::get<0>(item));
  }

  for (auto item : store) {
    fprintf(log_file, " mem ");
    commit_log_print_value(log_file, xlen, std::get<0>(item));
    fprintf(log_file, " ");
    commit_log_print_value(log_file, std::get<2>(item) << 3, std::get<1>(item));
  }
  fprintf(log_file, "\n");
}
#else
static void commit_log_reset(processor_t* p) {}
static void commit_log_stash_privilege(processor_t* p) {}
static void commit_log_print_insn(processor_t* p, reg_t pc, insn_t insn) {}
#endif

inline void processor_t::update_histogram(reg_t pc)
{
#ifdef RISCV_ENABLE_HISTOGRAM
  pc_histogram[pc]++;
#endif
}

// This is expected to be inlined by the compiler so each use of execute_insn
// includes a duplicated body of the function to get separate fetch.func
// function calls.
static inline reg_t execute_insn(processor_t* p, reg_t pc, insn_fetch_t fetch)
{
  commit_log_reset(p);
  commit_log_stash_privilege(p);
  reg_t npc;

  try {
    npc = fetch.func(p, fetch.insn, pc);
    if (npc != PC_SERIALIZE_BEFORE) {

#ifdef RISCV_ENABLE_COMMITLOG
      if (p->get_log_commits_enabled()) {
        commit_log_print_insn(p, pc, fetch.insn);
      }
#endif

     }
#ifdef RISCV_ENABLE_COMMITLOG
  } catch (wait_for_interrupt_t &t) {
      if (p->get_log_commits_enabled()) {
        commit_log_print_insn(p, pc, fetch.insn);
      }
      throw;
  } catch(mem_trap_t& t) {
      //handle segfault in midlle of vector load/store
      if (p->get_log_commits_enabled()) {
        for (auto item : p->get_state()->log_reg_write) {
          if ((item.first & 3) == 3) {
            commit_log_print_insn(p, pc, fetch.insn);
            break;
          }
        }
      }
      throw;
#endif
  } catch(...) {
    throw;
  }
  p->update_histogram(pc);

  return npc;
}

// determine whether the insn has rs1 field or not based on opcode and funct3 field
inline bool is_rs1(insn_t &insn){
  uint64_t opcode = insn.opcode();
  uint64_t funct3 = insn.funct3();
  switch(opcode){
    case 0x17:
    case 0x37:
    case 0x67:
    case 0x0f:
      return false;
    case 0x73:
      if(funct3 == 0x00 || funct3 == 0x05 || funct3 == 0x06 || funct3 == 0x07)
	return false;
      else
	return true;
    default:
      return true;
  }
}


// determine whether the insn has rs2 field or not based on opcode
inline bool is_rs2(insn_t &insn){
  uint64_t opcode = insn.opcode();
  switch(opcode){
    case 0x23:
    case 0x33:
    case 0x3b:
    case 0x63:
      return true;
    default:
      return false;
  }
}

inline bool detect_data_hazard(){ // detect data hazard
  if(IFIDinsn && IDEXinsn){
    if(is_mem_r(*IDEXinsn)){ //check whether IDEXinsn reads memory
      if((is_rs1(*IFIDinsn) && IDEXinsn->rd() == IFIDinsn->rs1()) || (is_rs2(*IFIDinsn) && IDEXinsn->rd() == IFIDinsn->rs2())) { //check data hazard between IDEX and IFID
	return true;
      }
    }
  }

  return false;
}

inline bool detect_control_hazard(reg_t old_pc){ // detect control hazard
  uint64_t opcode = IFIDinsn->opcode();

  if(opcode == 0x63 && ((branch_addr + 0x4) != old_pc)){ // check branch is taken
    return true; // if branch is taken, control hazard occurs
  }
  else if(opcode == 0x67 || opcode == 0x6f) return true;

  return false;
}

inline void clean_pipeline() { // clean pipeline when returning from main function
  if(IFIDinsn) cycle_num += 4;
  else if(IDEXinsn) cycle_num += 3;
  else if(EXMEMinsn) cycle_num += 2;
  else if(MEMWBinsn) cycle_num += 1;
  delete(IFIDinsn); IFIDinsn = NULL;
  delete(IDEXinsn); IDEXinsn = NULL;
  delete(EXMEMinsn); EXMEMinsn = NULL;
  delete(MEMWBinsn); MEMWBinsn = NULL;
}

inline reg_t update_pipeline(insn_t &insn, reg_t old_pc, insn_fetch_t fetch, processor_t *p){
  if(is_trap && old_pc == trap_addr){ // check whether trap handler is over
    is_trap = false;
  }

  if(old_pc == 0x0000000000010178){ // when entering main function
    is_main = true;
    return execute_insn(p, old_pc, fetch);
  }

  if(old_pc == 0x000000000001017C) { // when returning from main function
    clean_pipeline();
    printf("%ld\n", cycle_num);
    is_main = false;
    return execute_insn(p, old_pc, fetch);
  }

  if(is_main && !is_trap) { // check we are in main and not in trap handler
    //update pipeline
    delete(MEMWBinsn); MEMWBinsn = NULL;
    MEMWBinsn = EXMEMinsn;
    EXMEMinsn = IDEXinsn;
    uint64_t opcode = insn.opcode();

    if(opcode == 0x63) {// check if instruction is branch instruction
      branch_addr = old_pc;
    }

    if(detect_data_hazard()){ // when data hazard occurs, stall onecycle
      IDEXinsn = NULL;
      cycle_num++;
      if(opcode == 0x63 || opcode == 0x67 || opcode == 0x6f){ // if instruction is branch or jump, stall one more cycle 
        delete(MEMWBinsn); MEMWBinsn = NULL;
        MEMWBinsn = EXMEMinsn;
        EXMEMinsn = NULL;
        cycle_num++;
      }
      return old_pc; // return old_pc to re-fetch same instruction in next cycle
    }
    else{ // when data hazard does not occur
      if(IFIDinsn && detect_control_hazard(old_pc)){
        // when branch is taken or instruction is jump, stall one cycle
        delete(MEMWBinsn); MEMWBinsn = NULL;
        MEMWBinsn = EXMEMinsn;
        EXMEMinsn = IDEXinsn;
        IDEXinsn = NULL;
        cycle_num++;
      }
      else IDEXinsn = IFIDinsn;
      IFIDinsn = new insn_t(insn);
      cycle_num++;
      return execute_insn(p, old_pc, fetch);
    }
  }
  return execute_insn(p, old_pc, fetch);
}

bool processor_t::slow_path()
{
  return debug || state.single_step != state.STEP_NONE || state.debug_mode;
}

// fetch/decode/execute loop
void processor_t::step(size_t n)
{
  if (!state.debug_mode) {
    if (halt_request == HR_REGULAR) {
      enter_debug_mode(DCSR_CAUSE_DEBUGINT);
    } else if (halt_request == HR_GROUP) {
      enter_debug_mode(DCSR_CAUSE_GROUP);
    } // !!!The halt bit in DCSR is deprecated.
    else if (state.dcsr->halt) {
      enter_debug_mode(DCSR_CAUSE_HALT);
    }
  }

  while (n > 0) {
    size_t instret = 0;
    reg_t pc = state.pc;
    reg_t old_pc; // variable for saving address of instruction which will be executed in this cycle
    mmu_t* _mmu = mmu;

    #define advance_pc() \
     if (unlikely(invalid_pc(pc))) { \
       switch (pc) { \
         case PC_SERIALIZE_BEFORE: state.serialized = true; break; \
         case PC_SERIALIZE_AFTER: ++instret; break; \
         case PC_SERIALIZE_WFI: n = ++instret; break; \
         default: abort(); \
       } \
       pc = state.pc; \
       break; \
     } else { \
       state.pc = pc; \
       instret++; \
     }

    try
    {
      take_pending_interrupt();

      if (unlikely(slow_path()))
      {
        // Main simulation loop, slow path.
        while (instret < n)
        {
          if (unlikely(!state.serialized && state.single_step == state.STEP_STEPPED)) {
            state.single_step = state.STEP_NONE;
            if (!state.debug_mode) {
              enter_debug_mode(DCSR_CAUSE_STEP);
              // enter_debug_mode changed state.pc, so we can't just continue.
              break;
            }
          }

          if (unlikely(state.single_step == state.STEP_STEPPING)) {
            state.single_step = state.STEP_STEPPED;
          }

          insn_fetch_t fetch = mmu->load_insn(pc);
          if (debug && !state.serialized)
            disasm(fetch.insn);
          pc = execute_insn(this, pc, fetch);
          advance_pc();
        }
      }
      else while (instret < n)
      {
        // Main simulation loop, fast path.
        for (auto ic_entry = _mmu->access_icache(pc); ; ) {
          auto fetch = ic_entry->data;
          old_pc = pc; // save address of instruction which will be executed in this cycle
          pc = update_pipeline(fetch.insn, old_pc, fetch, this); // update pipeline and return address of instruction which will be executed in next cycle
          ic_entry = ic_entry->next;
          if (unlikely(ic_entry->tag != pc))
            break;
          if (unlikely(instret + 1 == n))
            break;
          instret++;
          state.pc = pc;
        }

        advance_pc();
      }
    }
    catch(trap_t& t)
    {
      if(is_main){ // when trap occurs in main
        insn_t insn = _mmu->access_icache(old_pc)->data.insn;
        const char *name = decode_inst(insn); // get name of current instruction
        if(!is_trap){ // check whether it is nested trap
          is_trap = true;
          if(!strcmp(name, "ecall")){  // when current instruction is ecall, stall once to simulate nop and wait for trap handler to be over
            trap_addr = pc + 4;
            delete(MEMWBinsn); MEMWBinsn = NULL;
            MEMWBinsn = EXMEMinsn;
            EXMEMinsn = IDEXinsn;
            IDEXinsn = IFIDinsn;
            IFIDinsn = NULL;
          } 
          else { // if current instruction is not ecall, simply wait for trap handler to be over
            trap_addr = pc;
            if(old_pc == pc) cycle_num--; // if current instruction is branch or jump, subract one cycle
          }
        }
      }
      take_trap(t, pc);
      n = instret;

      if (unlikely(state.single_step == state.STEP_STEPPED)) {
        state.single_step = state.STEP_NONE;
        enter_debug_mode(DCSR_CAUSE_STEP);
      }
    }
    catch (trigger_matched_t& t)
    {
      if (mmu->matched_trigger) {
        // This exception came from the MMU. That means the instruction hasn't
        // fully executed yet. We start it again, but this time it won't throw
        // an exception because matched_trigger is already set. (All memory
        // instructions are idempotent so restarting is safe.)

        insn_fetch_t fetch = mmu->load_insn(pc);
        pc = execute_insn(this, pc, fetch);
        advance_pc();

        delete mmu->matched_trigger;
        mmu->matched_trigger = NULL;
      }
      switch (state.mcontrol[t.index].action) {
        case ACTION_DEBUG_MODE:
          enter_debug_mode(DCSR_CAUSE_HWBP);
          break;
        case ACTION_DEBUG_EXCEPTION: {
          trap_breakpoint trap(state.v, t.address);
          take_trap(trap, pc);
          break;
        }
        default:
          abort();
      }
    }
    catch (wait_for_interrupt_t &t)
    {
      // Return to the outer simulation loop, which gives other devices/harts a
      // chance to generate interrupts.
      //
      // In the debug ROM this prevents us from wasting time looping, but also
      // allows us to switch to other threads only once per idle loop in case
      // there is activity.
      n = ++instret;
    }

    state.minstret->bump(instret);
    n -= instret;
  }
}
